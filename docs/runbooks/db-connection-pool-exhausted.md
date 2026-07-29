# Runbook — DBConnectionPoolExhausted (Pool de Conexões PostgreSQL Esgotado)

## 1. Impacto
* Bloqueio ou rejeição de comandos e consultas por ausência de conexões disponíveis com o banco de dados.
* Timeout nas requisições HTTP e erros 500/503.
* Nível de severidade: **CRITICAL**.

## 2. Sintomas
* Métrica `govsec_db_pool_available_connections < 2` por mais de 2 minutos.
* Log contendo erros do SQLAlchemy como `TimeoutError: QueuePool limit reached`.

## 3. Diagnóstico Seguro
1. Verificar contagem de conexões ativas no PostgreSQL:
   `psql -U govsec -d govsec -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"`
2. Consultar conexões presas em estado `idle in transaction`:
   `psql -U govsec -d govsec -c "SELECT pid, now() - state_change AS idle_duration, query FROM pg_stat_activity WHERE state = 'idle in transaction' ORDER BY idle_duration DESC;"`

## 4. Causas Prováveis
* Leaks de sessão (falha no fechamento de sessões SQLAlchemy AsyncSession).
* Transações longas sem commit ou rollback explícito.
* Subdimensionamento do parâmetro `pool_size` para a carga atual.

## 5. Comandos Reais e Não Destrutivos
* Inspecionar métrica do pool via `/metrics`:
  `curl -s http://localhost:8000/metrics | grep govsec_db_pool`

## 6. Recuperação
1. Se houver conexões órfãs em `idle in transaction` travando recursos, encerrar a conexão específica com autorização:
   `psql -U govsec -d govsec -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle in transaction' AND now() - state_change > interval '5 minutes';"`
2. Se necessário, reiniciar graciosamente a API para redefinir o pool SQLAlchemy.

## 7. Validação Pós-Recuperação
1. Confirmar que `govsec_db_pool_available_connections` retornou para >= 5.
2. Executar probe `/ready` para garantir resposta com status 200 OK.

## 8. Rollback
* Reverter ajustes no arquivo de configuração caso o tamanho do pool tenha sido alterado incorretamente.

## 9. Evidências a Preservar
* Lista de `pid` e consultas extraídas do `pg_stat_activity`.
* Log do SQLAlchemy indicando o momento do esgotamento.

## 10. Escalonamento
* Escalonar para o Administrador de Banco de Dados (DBA) / SRE de Banco de Dados.

## 11. Links Recomendados
* Dashboard Grafana DB Pool Panel: `http://localhost:3001/d/golden-signals`
