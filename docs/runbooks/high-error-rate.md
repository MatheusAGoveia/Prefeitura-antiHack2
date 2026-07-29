# Runbook — HighErrorRate (Taxa Elevada de Erros HTTP 5xx)

## 1. Impacto
* Falha no processamento de requisições de clientes, perda de ingestão ou recusa de comandos.
* Violação severa de SLO/SLA.
* Nível de severidade: **CRITICAL**.

## 2. Sintomas
* Respostas HTTP 5xx representando > 5% do volume total de tráfego por 5 minutos.
* Alerta `HighErrorRate` em estado `FIRING`.

## 3. Diagnóstico Seguro
1. Filtrar a taxa de respostas HTTP 5xx por endpoint:
   `sum(rate(http_requests_total{status_code=~"5.."}[5m])) by (endpoint, status_code)`
2. Inspecionar os logs estruturados JSON filtrados pelo nível `ERROR` e `CRITICAL`:
   `docker logs govsec-core-api 2>&1 | grep '"level":"ERROR"'`

## 4. Causas Prováveis
* Exceção não tratada em handler de Command ou Query.
* Perda de conexão com o banco de dados PostgreSQL (Connection Reset).
* Falha de autenticação interna ou rejeição pelo Security Kernel.

## 5. Comandos Reais e Não Destrutivos
* Verificar logs de erro com correlação no Loki/stdout:
  `docker logs --tail 200 govsec-core-api | grep -i "exception\|error"`

## 6. Recuperação
1. Identificar se os erros são provenientes do `RecoveryMiddleware` (exceções unhandled).
2. Se a causa for falha de conexão com banco ou cache, restabelecer a conectividade do contêiner.
3. Se for bug de código em rota recém-implantada, efetuar rollback imediato.

## 7. Validação Pós-Recuperação
1. Confirmar que a taxa de erros HTTP 5xx caiu para 0%.
2. Executar requisição de teste autenticada no endpoint afetado.

## 8. Rollback
* Executar rollback do deploy para a versão anterior estável via pipeline ou tag Docker.

## 9. Evidências a Preservar
* Logs com `recovery_id`, `trace_id` e stack trace completo da exceção.
* Registro de requisições malformadas ou com falha.

## 10. Escalonamento
* Escalonar imediatamente para o Arquiteto Principal / Plantão SRE de nível 2.

## 11. Links Recomendados
* Dashboard Grafana HTTP Errors: `http://localhost:3001/d/golden-signals`
* Grafana Loki Logs: `http://localhost:3001/explore`
