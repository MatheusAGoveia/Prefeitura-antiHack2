"""
Implementação do EventBus (Kafka via aiokafka / In-Memory Fallback)
GovSec Shield — Infrastructure Messaging
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from aiokafka import AIOKafkaProducer  # type: ignore[import-untyped]

from src.core.application.interfaces import IEventPublisher
from src.core.domain.events import DomainEvent
from src.core.infrastructure.config import settings

logger = logging.getLogger(__name__)


class EventBus(IEventPublisher):
    """
    EventBus assíncrono compatível com Redpanda/Kafka e fallback In-Memory.
    """

    def __init__(
        self, bootstrap_servers: str = settings.GOVSEC_KAFKA_BOOTSTRAP, use_kafka: bool = False
    ):
        self.bootstrap_servers = bootstrap_servers
        self.use_kafka = use_kafka
        self._listeners: dict[str, list[Callable[..., Any]]] = {}
        self._producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        if self.use_kafka:
            try:
                self._producer = AIOKafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                )
                await self._producer.start()
                logger.info("Kafka AIOProducer iniciado com sucesso.")
            except Exception as e:
                if settings.GOVSEC_ENV in ("staging", "production"):
                    raise RuntimeError(
                        f"Falha ao conectar ao Kafka em ambiente '{settings.GOVSEC_ENV}': {e}. "
                        "Fallback in-memory é estritamente proibido em produção."
                    ) from e
                logger.warning(
                    f"Falha ao conectar ao Redpanda/Kafka ({e}). Alternando para EventBus In-Memory."
                )
                self.use_kafka = False


    async def stop(self) -> None:
        if self._producer:
            await self._producer.stop()

    def subscribe(self, event_type: str, handler: Callable[..., Any]) -> None:
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(handler)

    async def publish(self, event: DomainEvent) -> None:
        event_dict = event.model_dump(mode="json")
        logger.info(f"[EVENT PUBLISHED] EventType={event.event_type} EventID={event.event_id}")

        if self.use_kafka and self._producer:
            topic = f"{settings.GOVSEC_KAFKA_TOPIC_PREFIX}.events"
            key = str(event.tenant_id).encode("utf-8") if event.tenant_id else None
            await self._producer.send_and_wait(topic, value=event_dict, key=key)
        else:
            # Fallback In-Memory dispatch
            listeners = self._listeners.get(event.event_type, [])
            for listener in listeners:
                try:
                    await listener(event)
                except Exception as exc:
                    logger.error(
                        f"Erro ao processar listener para evento {event.event_type}: {exc}"
                    )
