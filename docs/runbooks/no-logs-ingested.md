# Runbook — NoLogsIngested (Ausência de Ingestão de Logs)

## 1. Impacto
* Perda de visibilidade de auditoria e falha na coleta de eventos de segurança.
* Risco de desconformidade regulatória e atraso na detecção de ameaças.
* Nível de severidade: **WARNING**.

## 2. Sintomas
* Métrica `increase(govsec_logs_ingested_total[15m]) == 0` enquanto a API está UP.
* Alerta `NoLogsIngested` em estado `FIRING`.

## 3. Diagnóstico Seguro
1. Inspecionar valor atual do contador Prometheus:
   `curl -s http://localhost:8000/metrics | grep govsec_logs_ingested_total`
2. Testar o envio de um log sintético via endpoint REST `/api/v1/logs`.
3. Verificar integridade da tabela `audit_logs` no PostgreSQL:
   `psql -U govsec -d govsec -c "SELECT count(*), max(timestamp) FROM audit_logs;"`

## 4. Causas Prováveis
* Interrupção de conectores externos (Zabbix, Wazuh, Syslog Adapters).
* Bloqueio ou falha de autenticação dos clientes de ingestão.
* Falha de escrita na tabela de auditoria do PostgreSQL.

## 5. Comandos Reais e Não Destrutivos
* Enviar log de teste via `curl` autenticado para validar o pipeline:
  `curl -X POST http://localhost:8000/api/v1/logs -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{"source":"test-runbook","raw_data":"test","tenant_id":"00000000-0000-0000-0000-000000000001"}'`

## 6. Recuperação
1. Se a falha for de conectores externos, reiniciar a camada de adaptadores ACL.
2. Se a falha for no banco de dados, verificar logs do PostgreSQL e restabelecer permissões/espaço em disco.

## 7. Validação Pós-Recuperação
1. Confirmar que o contador `govsec_logs_ingested_total` voltou a ser incrementado.
2. Verificar se o alerta `NoLogsIngested` transita para estado `RESOLVED`.

## 8. Rollback
* Reverter regras de firewall ou bloqueios de IP recentes nos conectores de ingestão.

## 9. Evidências a Preservar
* Registros de timestamps do último log gravado no PostgreSQL.
* Logs do conector externo com erro de entrega.

## 10. Escalonamento
* Escalonar para a equipe de Integrações & SOC.

## 11. Links Recomendados
* Dashboard Grafana Log Ingestion Panel: `http://localhost:3001/d/golden-signals`
