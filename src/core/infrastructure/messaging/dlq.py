"""
Dead Letter Queue (DLQ) para Mensagens e Comandos com Falhas Permanentes
GovSec Shield — Infrastructure Messaging DLQ
"""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger("govsec.messaging.dlq")


class DeadLetterQueue:
    """
    Fila de mensagens com falhas (DLQ) para auditoria e repasse manual.
    """

    _instance: "DeadLetterQueue | None" = None
    _queue: list[dict[str, Any]] = []

    def __new__(cls) -> "DeadLetterQueue":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._queue = []
        return cls._instance

    def send_to_dlq(self, message: dict[str, Any], error: str | Exception) -> str:
        dlq_id = f"dlq-{uuid4().hex[:8]}"
        err_msg = str(error)

        dlq_entry = {
            "dlq_id": dlq_id,
            "message": message,
            "error": err_msg,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "status": "PENDING_RETRY",
        }

        self._queue.append(dlq_entry)
        logger.error(
            "DLQ_EVENT | dlq_id=%s message_type=%s error=%s",
            dlq_id,
            message.get("type") or message.get("event_type") or "UnknownCommand",
            err_msg,
        )
        return dlq_id

    def get_failed_messages(self) -> list[dict[str, Any]]:
        return list(self._queue)

    def requeue_message(self, dlq_id: str, bus: Any) -> bool:
        for entry in self._queue:
            if entry["dlq_id"] == dlq_id and entry["status"] != "RESOLVED":
                entry["status"] = "REQUEUED"
                logger.info("DLQ_REQUEUE | dlq_id=%s reenfileirando mensagem...", dlq_id)
                return True
        return False

    def clear(self) -> None:
        self._queue.clear()
