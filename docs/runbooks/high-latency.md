# Runbook — HighLatency (Alta Latência p95 na API)

## 1. Impacto
* Lentidão no processamento de requisições REST e degradação na experiência do usuário.
* Acúmulo de requisições simultâneas e potencial esgotamento do worker loop.
* Nível de severidade: **WARNING**.

## 2. Sintomas
* Histograma `http_request_duration_seconds` com p95 > 1.0 segundo por 5 minutos contínuos.
* Alerta `HighLatency` em estado `FIRING`.

## 3. Diagnóstico Seguro
1. Consultar os percentis de latência por endpoint no Grafana.
2. Identificar endpoints lentos via PromQL:
   `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, endpoint))`
3. Verificar uso de CPU e memória do processo da API.

## 4. Causas Prováveis
* Lock de banco de dados ou consultas lentas (Slow Queries).
* Contenção no pool de conexões com o PostgreSQL.
* Chamadas de rede síncronas bloqueantes ou timeout de conectores externos (OPA, Kafka).

## 5. Comandos Reais e Não Destrutivos
* Consultar queries ativas e tempo de execução no PostgreSQL:
  `psql -U govsec -d govsec -c "SELECT pid, now() - query_start AS duration, query FROM pg_stat_activity WHERE state != 'idle' ORDER BY duration DESC LIMIT 5;"`
* Verificar file descriptors e threads abertas:
  `cat /proc/$(pgrep uvicorn)/status`

## 6. Recuperação
1. Identificar se o gargalo é isolado a um endpoint ou global.
2. Se houver contensão no OPA Engine ou Kafka, verificar a saúde dessas dependências.
3. Se necessário, aumentar horizontalmente o número de workers do Uvicorn.

## 7. Validação Pós-Recuperação
1. Monitorar o gráfico p95 no Grafana por 10 minutos após intervenção.
2. Garantir que a métrica retorne para < 250ms em tráfego nominal.

## 8. Rollback
* Reverter otimizações temporárias de infraestrutura ou deploys recentes se a latência tiver surgido após nova release.

## 9. Evidências a Preservar
* Traces distribuídos no Grafana Tempo com alta duração.
* Logs do `pg_stat_activity` e slow query log do PostgreSQL.

## 10. Escalonamento
* Escalonar para o Líder Técnico de Backend se o p95 permanecer > 2s por 30 minutos.

## 11. Links Recomendados
* Dashboard Grafana Latency Panel: `http://localhost:3001/d/golden-signals`
* Grafana Tempo Traces: `http://localhost:3001/explore`
