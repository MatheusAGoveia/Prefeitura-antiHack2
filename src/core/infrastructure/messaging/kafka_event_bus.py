"""
Kafka Event Bus com aiokafka, Deduplicação e Fallback In-Memory
GovSec Shield — Infrastructure Messaging
"""

import contextlib
import json
import logging
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer  # type: ignore[import-untyped]

from src.core.domain.events import DomainEvent
from src.core.infrastructure.config import settings
from src.core.infrastructure.messaging.event_bus import EventBus

logger = logging.getLogger("govsec.messaging.kafka")


class KafkaEventBus(EventBus):
    """
    Barramento de eventos assíncrono Kafka/Redpanda com garantia de Idempotência e Fallback.
    """

    def __init__(
        self,
        bootstrap_servers: str = settings.GOVSEC_KAFKA_BOOTSTRAP,
        use_kafka: bool = False,
        allow_fallback: bool | None = None,
    ):
        super().__init__(bootstrap_servers=bootstrap_servers, use_kafka=use_kafka)
        current_env = getattr(settings, "GOVSEC_ENV", "dev")
        if allow_fallback is None:
            self.allow_fallback = current_env in ("development", "dev", "test") and not use_kafka
        else:
            self.allow_fallback = allow_fallback
        self._processed_events: set[str] = set()
        self._consumers: list[AIOKafkaConsumer] = []

    async def start(self) -> None:
        if self.use_kafka:
            try:
                self._producer = AIOKafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                    request_timeout_ms=3000,
                )
                await self._producer.start()
                logger.info("Kafka AIOProducer iniciado com sucesso em %s", self.bootstrap_servers)
            except Exception as e:
                current_env = getattr(settings, "GOVSEC_ENV", "dev")
                if current_env in ("staging", "production") or not self.allow_fallback:
                    logger.error(
                        "Falha crítica ao conectar ao Kafka em %s (%s). Fallback em memória estritamente proibido.",
                        self.bootstrap_servers,
                        e,
                    )
                    raise RuntimeError(
                        f"Falha de conexão com Kafka/Redpanda em ambiente '{current_env}': {e}"
                    ) from e
                logger.warning(
                    "Falha ao conectar ao Redpanda/Kafka (%s). Alternando para Fallback In-Memory em dev/test.", e
                )
                self.use_kafka = False

    async def stop(self) -> None:
        for consumer in self._consumers:
            with contextlib.suppress(Exception):
                await consumer.stop()

        if self._producer:
            await self._producer.stop()
            logger.info("Kafka AIOProducer finalizado com sucesso.")

    def is_duplicate(self, correlation_id: str) -> bool:
        if correlation_id in self._processed_events:
            return True
        self._processed_events.add(correlation_id)
        return False

    async def publish(self, event: dict[str, Any] | DomainEvent) -> None:
        if isinstance(event, DomainEvent):
            event_dict = event.model_dump(mode="json")
            event_type = event.event_type
            correlation_id = getattr(event, "correlation_id", None) or event.event_id
            tenant_id = str(event.tenant_id) if event.tenant_id else "global"
        elif isinstance(event, dict):
            event_dict = event
            event_type = event.get("type") or event.get("event_type") or "GenericEvent"
            correlation_id = event.get("correlation_id") or event.get("id") or str(uuid4())
            tenant_id = event.get("tenant") or event.get("tenant_id") or "global"
        else:
            raise ValueError("Evento deve ser um dicionário ou subclasse de DomainEvent.")

        # Checar idempotência de desduplicação
        if self.is_duplicate(str(correlation_id)):
            logger.warning("EVENT_DUPLICATE_SKIPPED | correlation_id=%s", correlation_id)
            return

        logger.info("[EVENT_PUBLISHED] event_type=%s correlation_id=%s", event_type, correlation_id)

        if self.use_kafka:
            if not self._producer:
                raise RuntimeError("Kafka AIOProducer não está ativo ou inicializado.")
            topic = f"{settings.GOVSEC_KAFKA_TOPIC_PREFIX}.events"
            key = tenant_id.encode("utf-8")
            try:
                await self._producer.send_and_wait(topic, value=event_dict, key=key)
            except Exception as exc:
                logger.error("Falha ao publicar evento no Kafka/Redpanda: %s", exc)
                raise RuntimeError(f"Falha na entrega do evento ao Kafka: {exc}") from exc
        else:
            current_env = getattr(settings, "GOVSEC_ENV", "dev")
            if current_env in ("staging", "production") or not self.allow_fallback:
                raise RuntimeError(
                    f"Tentativa de publicação in-memory proibida no ambiente '{current_env}' sem Kafka ativado."
                )
            # Fallback In-Memory dispatch
            listeners = self._listeners.get(event_type, [])
            for listener in listeners:
                try:
                    await listener(event_dict if isinstance(event, dict) else event)
                except Exception as exc:
                    logger.error("Erro ao processar listener para %s: %s", event_type, exc)

    def subscribe(self, topic: str, callback: Callable[..., Any]) -> None:
        super().subscribe(topic, callback)
        if self.use_kafka:
            logger.info("Inscrição Kafka agendada para o tópico '%s'.", topic)
