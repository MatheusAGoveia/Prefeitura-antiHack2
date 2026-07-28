"""
OpenTelemetry Tracing Setup e Utilities
GovSec Shield — Shared Observability
"""

import os
from collections.abc import Generator
from contextlib import contextmanager, suppress
from typing import Any

from opentelemetry import propagate, trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.trace import Span, Tracer
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

_TRACER_NAME = "govsec.shield"
_tracer: Tracer | None = None


def setup_tracing(service_name: str = "govsec-shield-api") -> TracerProvider:
    """
    Configura o OpenTelemetry TracerProvider, propagação W3C e exportadores.
    Evita re-inicialização caso o Provider já esteja configurado.
    """
    current = trace.get_tracer_provider()
    if isinstance(current, TracerProvider):
        global _tracer
        if _tracer is None:
            _tracer = trace.get_tracer(_TRACER_NAME)
        return current

    resource = Resource.create(attributes={SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    # Configurar exportador: OTLP Span Exporter se configurado via env var, senão Console/In-Memory Exporter
    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except (ImportError, Exception):
            # Fallback para console caso pacote otlp grpc não esteja instalado
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    else:
        # Modo de desenvolvimento local ou teste
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    with suppress(Exception):
        trace.set_tracer_provider(provider)


    # Configurar propagação global W3C Trace Context
    propagate.set_global_textmap(TraceContextTextMapPropagator())

    _tracer = trace.get_tracer(_TRACER_NAME)
    return provider


def get_tracer() -> Tracer:
    """Retorna a instância global do OpenTelemetry Tracer."""
    global _tracer
    if _tracer is None:
        _tracer = trace.get_tracer(_TRACER_NAME)
    return _tracer


def instrument_fastapi(app: Any) -> None:
    """Instrumenta a aplicação FastAPI para criação automática de Spans OpenTelemetry."""
    with suppress(Exception):
        FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())



@contextmanager
def trace_span(name: str, attributes: dict[str, Any] | None = None) -> Generator[Span, None, None]:
    """
    Context manager utilitário para criar spans customizados de tracing.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for key, value in attributes.items():
                if value is not None:
                    span.set_attribute(key, str(value))
        yield span
