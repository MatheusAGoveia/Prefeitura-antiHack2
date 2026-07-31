"""
Consumidor Kafka Independente para o Motor de Correlação.
GovSec Shield — Infrastructure Messaging (M3.2)

Este consumidor é 100% DESACOPLADO da outbox (propriedade exclusiva do OutboxDispatcher).
Ele consome eventos SecurityEventReceivedEvent publicados no Kafka/Redpanda e aciona
o CorrelateSecurityEventHandler.

Fluxo:
  1. aiokafka.AIOKafkaConsumer subscreve no tópico 'govsec.security-events'.
  2. Consumer Group: 'govsec-correlation-group' (configurável por env var).
  3. Para cada mensagem:
     a. Abre uma transação isolada de banco de dados (CorrelationUnitOfWork).
     b. Executa CorrelateSecurityEventHandler.handle(tenant_id, security_event_id).
     c. Executa uow.commit() para salvar incidente/evidência.
     d. Confirma offset no Kafka SOMENTE APÓS o commit bem-sucedido no DB (await consumer.commit()).
  4. Se o commit do DB falhar, o offset NÃO é confirmado e o Kafka reentregará a mensagem.

Segurança & Observabilidade:
  - Logs estruturados sem payload sensível.
  - Nenhum toque ou modificação na tabela outbox_events.
"""

import asyncio
import json
import logging
from collections.abc import Callable
from uuid import UUID

from aiokafka import AIOKafkaConsumer

from src.core.application.correlation_handler import CorrelateSecurityEventHandler
from src.core.application.interfaces.uow import CorrelationUnitOfWork
from src.core.domain.correlation import CorrelationRule
from src.core.infrastructure.config import settings
from src.core.infrastructure.correlation.rules import get_rules_for_tenant

logger = logging.getLogger(__name__)


class CorrelationKafkaConsumer:
    """
    Consumidor Kafka operacional para o Motor de Correlação (M3.2).
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        group_id: str | None = None,
        topic: str | None = None,
        uow_factory: Callable[[], CorrelationUnitOfWork] | None = None,
        rules_factory: Callable[[UUID], list[CorrelationRule]] | None = None,
        window_seconds: int = 3600,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers or settings.GOVSEC_KAFKA_BOOTSTRAP
        self._group_id = group_id or settings.GOVSEC_KAFKA_CORRELATION_GROUP_ID
        prefix = settings.GOVSEC_KAFKA_TOPIC_PREFIX
        self._topic = topic or f"{prefix}.security-events"
        self._uow_factory = uow_factory
        self._rules_factory = rules_factory or get_rules_for_tenant
        self._window_seconds = window_seconds
        self._consumer: AIOKafkaConsumer | None = None
        self._running = False

    async def start(self) -> None:
        """Inicia o consumidor Kafka."""
        if self._consumer is not None:
            return

        logger.info(
            "Iniciando CorrelationKafkaConsumer. bootstrap=%s group_id=%s topic=%s",
            self._bootstrap_servers,
            self._group_id,
            self._topic,
        )

        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap_servers,
            group_id=self._group_id,
            enable_auto_commit=False,  # Desabilitado auto-commit para garantir commit pós-DB
            auto_offset_reset="earliest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            request_timeout_ms=5000,
        )
        await self._consumer.start()
        self._running = True
        logger.info("CorrelationKafkaConsumer iniciado com sucesso.")

    async def stop(self) -> None:
        """Encerra o consumidor Kafka graciosamente."""
        self._running = False
        if self._consumer is not None:
            try:
                await self._consumer.stop()
                logger.info("CorrelationKafkaConsumer parado com sucesso.")
            except Exception as exc:
                logger.error("Erro ao parar CorrelationKafkaConsumer: %s", exc)
            finally:
                self._consumer = None

    async def process_single_message(self, msg_value: dict) -> bool:
        """
        Processa o payload de um único evento Kafka.
        Retorna True se processado e commitado com sucesso no DB.
        """
        event_type = msg_value.get("event_type")
        if event_type != "SecurityEventReceivedEvent":
            # Ignora outros tipos de eventos no mesmo tópico
            return True

        tenant_id_str = msg_value.get("tenant_id")
        event_id_str = msg_value.get("security_event_id")

        if not tenant_id_str or not event_id_str:
            logger.warning(
                "CorrelationKafkaConsumer: evento sem tenant_id ou security_event_id. Ignorando."
            )
            return True

        try:
            tenant_id = UUID(str(tenant_id_str))
            security_event_id = UUID(str(event_id_str))
        except (ValueError, TypeError) as exc:
            logger.error("CorrelationKafkaConsumer: UUIDs inválidos no payload Kafka: %s", exc)
            return True

        if self._uow_factory is None:
            from src.core.infrastructure.db.repositories import PostgresCorrelationUnitOfWork
            from src.core.infrastructure.db.unit_of_work import async_session_factory

            async def default_uow_factory() -> PostgresCorrelationUnitOfWork:
                return PostgresCorrelationUnitOfWork(async_session_factory())

            uow_factory = default_uow_factory
        else:
            uow_factory = self._uow_factory

        # Execução isolada em transação DB
        try:
            async with uow_factory() as uow:
                # Carregar regras de correlação ativas para o tenant
                rules = self._rules_factory(tenant_id)
                active_rules: list[CorrelationRule] = []

                # Filtrar apenas regras catalogadas como ativas no banco se houver
                db_rule_versions = await uow.correlation_rules.list_active()
                active_rule_keys = {
                    (r.rule_id, r.rule_version) for r in db_rule_versions if r.is_active
                }

                if db_rule_versions:
                    for r in rules:
                        if (r.rule_id, r.version) in active_rule_keys:
                            active_rules.append(r)
                else:
                    # Se catálogo no banco estiver vazio, usa as regras padrão ativas
                    active_rules = rules

                handler = CorrelateSecurityEventHandler(
                    uow=uow,
                    rules=active_rules,
                    window_seconds=self._window_seconds,
                )
                await handler.handle(
                    tenant_id=tenant_id,
                    security_event_id=security_event_id,
                )

                # Commit no Banco de Dados
                await uow.commit()

            logger.info(
                "CorrelationKafkaConsumer: evento correlacionado e commitado no DB. "
                "tenant_id=%s event_id=%s",
                tenant_id,
                security_event_id,
            )
            return True

        except Exception as exc:
            logger.error(
                "CorrelationKafkaConsumer: erro ao correlacionar evento %s no DB: %s",
                event_id_str,
                exc,
                exc_info=True,
            )
            return False

    async def run(self) -> None:
        """Loop principal de consumo do Kafka."""
        if self._consumer is None:
            await self.start()

        assert self._consumer is not None

        logger.info("CorrelationKafkaConsumer: iniciando loop de consumo de eventos Kafka...")
        try:
            while self._running:
                try:
                    msg_batch = await self._consumer.getmany(timeout_ms=1000, max_records=10)
                    for topic_partition, msgs in msg_batch.items():
                        for msg in msgs:
                            if not self._running:
                                break
                            success = await self.process_single_message(msg.value)
                            if success:
                                # Offset Kafka só é confirmado APÓS commit bem-sucedido do banco!
                                await self._consumer.commit({topic_partition: msg.offset + 1})
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.error("Erro no loop do CorrelationKafkaConsumer: %s", exc)
                    await asyncio.sleep(1)
        finally:
            await self.stop()
