# ADR 006: Scrape Autoritativo de Métricas — HTTP 500 em Falha do PostgreSQL

## Status
Aceito

## Data
2026-07-31

## Contexto

O endpoint `GET /metrics` do GovSec Shield expõe o Gauge `govsec_open_incidents{severity}` ao Prometheus. Este Gauge representa a contagem atual de incidentes abertos por severidade, tendo o PostgreSQL como **única fonte de verdade**.

### Problema da Implementação Anterior

A implementação anterior chamava `safe_sync_open_incidents_gauge_from_db()` no handler do endpoint `/metrics`. O adaptador `safe_*` captura silenciosamente qualquer exceção de banco de dados, registra um `WARNING` no log e retorna sem atualizar o Gauge.

**Consequência:** Quando o PostgreSQL estava indisponível, o endpoint retornava `HTTP 200 OK` com o valor **stale** do Gauge (última leitura bem-sucedida). O Prometheus aceitava esses dados como válidos, mascarando a indisponibilidade do banco e podendo ocultar incidentes críticos que tinham sido abertos ou fechados desde a última sincronização.

### Requisito Arquitetural

O GovSec Shield opera em ambiente governamental municipal onde a acurácia do estado de incidentes é crítica para a segurança operacional. Apresentar dados stale de incidentes abertos ao Prometheus é funcionalmente equivalente a apresentar um estado falso.

---

## Decisão

O `metrics_endpoint_handler` usa `sync_open_incidents_gauge_from_db()` (sem adaptador `safe_*`) envolvido em um bloco `try/except` explícito que, em caso de falha, lança `HTTPException(status_code=500, detail="Database unavailable for metrics scrape")`.

```python
async def metrics_endpoint_handler(session: Any = Depends(get_db_session)) -> Response:
    try:
        await sync_open_incidents_gauge_from_db(session)
    except Exception as exc:
        logger.error("Falha ao consultar PostgreSQL no scrape autoritativo de /metrics: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database unavailable for metrics scrape",
        ) from exc

    collect_db_pool_metrics()
    data: bytes = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
```

### Separação de Responsabilidades: `safe_*` vs. Autoritativo

| Função | Uso | Comportamento em Falha |
|:---|:---|:---|
| `sync_open_incidents_gauge_from_db()` | Scrape autoritativo `/metrics` | Propaga exceção → HTTP 500 |
| `safe_sync_open_incidents_gauge_from_db()` | Fluxos não-críticos (pós-commit Kafka) | Captura exceção, loga `WARNING`, preserva Gauge stale |

O adaptador `safe_*` é mantido e continua correto para uso no consumidor Kafka, onde uma falha de observabilidade pós-commit **não deve** reverter a transação já confirmada nem interromper a confirmação do offset.

---

## Consequências

### Positivas

- **Sem dados stale apresentados como válidos:** Quando o banco está indisponível, o Prometheus registra a raspagem como falha (`up=0`), o que aciona alertas de `ScrapeFailed` em vez de consumir silenciosamente dados desatualizados.
- **Auditabilidade do estado real:** O log de `ERROR` emitido antes do `HTTPException` mantém rastreabilidade da falha com `trace_id` e `correlation_id`.
- **Comportamento Prometheus consistente:** Com `up=0`, dashboards Grafana exibem lacunas visíveis no histórico em vez de linhas planas potencialmente enganosas.
- **Zero Trust aplicado à observabilidade:** Dados não confirmados como atuais pelo banco não são publicados ao sistema de monitoramento.

### Negativas / Trade-offs

- **Raspage falha durante indisponibilidade do banco:** O Prometheus marca o target como `down` durante a janela de falha do PostgreSQL. Isso é o comportamento correto, mas pode disparar falsos alertas de `IncidentGaugeStale` se o alerta não distinguir falha de scrape de valor stale.
- **Dependência de conectividade:** O endpoint `/metrics`, que era tolerante a falhas de banco, passa a depender da disponibilidade do PostgreSQL. Isso é aceitável dado que o GovSec Shield já depende do PostgreSQL para todos os outros endpoints críticos.

---

## Alternativas Consideradas

### Alternativa 1: Retornar dados stale com header `X-Data-Stale: true`
**Rejeitada.** O Prometheus não interpreta headers customizados. O scrape seria aceito como válido e os dados stale seriam gravados no TSDB.

### Alternativa 2: Manter `safe_*` e adicionar uma métrica separada `govsec_metrics_db_sync_error`
**Rejeitada.** Aumenta a complexidade de instrumentação sem resolver o problema central: o Gauge continuaria apresentando valores stale como estado atual.

### Alternativa 3: Cache de 30s com TTL explícito no handler
**Rejeitada.** Introduz estado compartilhado mútável no handler, viola o princípio de imutabilidade e torna o comportamento não determinístico em ambientes multi-réplica.

---

## Validação

- `test_db_failure_during_scrape_returns_http_500`: comprova via `async_client.get("/metrics")` com `PostgresIncidentRepository.count_open_by_severity` patchado como `SQLAlchemyError` → `HTTP 500` confirmado.
- `test_dynamic_metrics_scrape_reflects_worker_created_incident`: comprova que o valor exato retornado pelo scrape corresponde a `count_open_by_severity()` do banco.
- Todos os 9 gates executados em 2026-07-31T19:32–19:33 UTC. **230 PASSED, 0 FAILED.**

---

## Referências

- `src/shared/observability/metrics.py` — `metrics_endpoint_handler`, `sync_open_incidents_gauge_from_db`, `safe_sync_open_incidents_gauge_from_db`
- `tests/integration/test_m3_3_incident_operations.py` — `test_db_failure_during_scrape_returns_http_500`
- `ADR-005` — Correlação Determinística e Central de Incidentes (define PostgreSQL como fonte de verdade)
- `MEMORIA.md` — Histórico completo de execução de gates M3.3
