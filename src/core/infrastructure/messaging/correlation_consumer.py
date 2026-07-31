"""
Consumidor Kafka Independente para o Motor de Correlação.
GovSec Shield — Infrastructure Messaging (M3.2)

Este consumidor é 100% DESACOPLADO da outbox (propriedade exclusiva do OutboxDispatcher).
Ele consome eventos SecurityEventReceivedEvent publicados no Kafka/Redpanda e aciona
o CorrelateSecurityEventHandler.

Fluxo:
  1. aiokafka.AIOKafkaConsumer subscreve no tópico 'govsec.events'.
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
import contextlib
import json
import logging
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

from aiokafka import AIOKafkaConsumer
from aiokafka.errors import KafkaError
from sqlalchemy.exc import SQLAlchemyError

from src.core.application.correlation_handler import CorrelateSecurityEventHandler
from src.core.application.interfaces.uow import CorrelationUnitOfWork
from src.core.domain.correlation import CorrelationRule
from src.core.infrastructure.config import settings
from src.core.infrastructure.correlation.rules import get_rules_for_tenant

logger = logging.getLogger(__name__)

READINESS_FILE_PATH = Path(tempfile.gettempdir()) / "correlation-worker.ready"


def default_correlation_uow_factory() -> CorrelationUnitOfWork:
    """Fábrica padrão síncrona que instancia uma CorrelationUnitOfWork pronta para uso em gerenciador de contexto assíncrono."""
    from src.core.infrastructure.db.repositories import PostgresCorrelationUnitOfWork
    from src.core.infrastructure.db.unit_of_work import AsyncSessionLocal

    return PostgresCorrelationUnitOfWork(AsyncSessionLocal())


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
        self._topic = topic or f"{prefix}.events"
        self._uow_factory = uow_factory or default_correlation_uow_factory
        self._rules_factory = rules_factory or get_rules_for_tenant
        self._window_seconds = window_seconds
        self._consumer: AIOKafkaConsumer | None = None
        self._running = False

    @staticmethod
    def _create_readiness_file() -> None:
        try:
            READINESS_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
            READINESS_FILE_PATH.touch(exist_ok=True)
            logger.info("Arquivo de readiness do correlation-worker criado em %s", READINESS_FILE_PATH)
        except OSError as exc:
            logger.warning("Falha ao criar arquivo de readiness do correlation-worker: %s", exc)

    @staticmethod
    def _remove_readiness_file() -> None:
        with contextlib.suppress(Exception):
            if READINESS_FILE_PATH.exists():
                READINESS_FILE_PATH.unlink()
                logger.info("Arquivo de readiness do correlation-worker removido.")

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

        try:
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
            self._create_readiness_file()
            logger.info("CorrelationKafkaConsumer iniciado com sucesso.")
        except KafkaError as exc:
            logger.error("Falha de rede/broker Kafka ao inicializar CorrelationKafkaConsumer: %s", exc)
            self._remove_readiness_file()
            raise
        except OSError as exc:
            logger.error("Falha de I/O de sistema ao inicializar CorrelationKafkaConsumer: %s", exc)
            self._remove_readiness_file()
            raise
        except Exception as exc:
            # Justificativa Técnica: No limite da inicialização do componente de infraestrutura, qualquer exceção
            # inesperada deve impedir a criação do readiness file, garantir a remoção de resíduos e propagar a falha
            # ao processo chamador para reinício pelo orquestrador (Docker Compose/K8s).
            logger.error("Falha inesperada ao inicializar CorrelationKafkaConsumer: %s", exc)
            self._remove_readiness_file()
            raise

    async def stop(self) -> None:
        """Encerra o consumidor Kafka graciosamente."""
        self._running = False
        self._remove_readiness_file()
        if self._consumer is not None:
            try:
                await self._consumer.stop()
                logger.info("CorrelationKafkaConsumer parado com sucesso.")
            except KafkaError as exc:
                logger.error("Erro Kafka ao parar CorrelationKafkaConsumer: %s", exc)
            except Exception as exc:
                logger.error("Erro inesperado ao parar CorrelationKafkaConsumer: %s", exc)
            finally:
                self._consumer = None

    async def process_single_message(self, msg_value: dict[str, Any]) -> bool:
        """
        Processa o payload de um único evento Kafka.
        Retorna True se processado e commitado com sucesso no DB.
        Retorna False se o banco de dados falhar, abortando o commit do offset no Kafka.
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

        # Execução isolada em transação DB
        try:
            uow_or_coro = self._uow_factory()
            if asyncio.iscoroutine(uow_or_coro):
                uow = await uow_or_coro
            else:
                uow = uow_or_coro

            async with uow:
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

        except SQLAlchemyError as exc:
            # Captura explícita de exceção de banco de dados para abortar o commit de offset
            logger.error(
                "CorrelationKafkaConsumer: erro de banco de dados ao correlacionar evento %s: %s",
                event_id_str,
                exc,
                exc_info=True,
            )
            return False
        except Exception as exc:
            # Justificativa Técnica: No limite da execução da transação de correlação, qualquer exceção não
            # esperada (ex: erro inesperado de domínio/handler) deve impedir o commit do offset no Kafka
            # garantindo que o evento permaneça não confirmado para reentrega e diagnóstico.
            logger.error(
                "CorrelationKafkaConsumer: exceção não tratada ao correlacionar evento %s no DB: %s",
                event_id_str,
                exc,
                exc_info=True,
            )
            return False

    async def run(self) -> None:
        """Loop principal de consumo do Kafka."""
        if self._consumer is None:
            await self.start()

        if self._consumer is None:
            raise RuntimeError("Consumidor Kafka não foi inicializado com sucesso.")

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
                except KafkaError as exc:
                    logger.error("Erro de comunicação Kafka no loop do CorrelationKafkaConsumer: %s", exc)
                    await asyncio.sleep(1)
                except Exception as exc:
                    # Justificativa Técnica: A captura no nível superior do loop de polling impede que um picos
                    # ou falha transitória em uma iteração encerre abruptamente a tarefa do consumidor.
                    logger.error("Exceção não tratada no loop principal do CorrelationKafkaConsumer: %s", exc)
                    await asyncio.sleep(1)
        finally:
            await self.stop()
