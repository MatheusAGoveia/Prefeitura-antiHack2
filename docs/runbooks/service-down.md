# Runbook — ServiceDown (API Principal Indisponível)

## 1. Impacto
* Parada total no recebimento de comandos CQRS e ingestão de auditoria.
* Usuários e integrações recebem falha de conexão (Connection Refused ou Timeout).
* Nível de severidade: **CRITICAL**.

## 2. Sintomas
* Probe `/healthz` ou `/ready` inatingível.
* Métrica `up{job="govsec-core-api"} == 0` por mais de 1 minuto.
* Falha de resolução de nomes ou escuta na porta `8000`.

## 3. Diagnóstico Seguro
1. Verificar status dos contêineres e processos sem aplicar mutação:
   `docker ps --filter "name=govsec-core-api"`
2. Inspecionar as últimas 100 linhas dos logs da API:
   `docker logs --tail 100 govsec-core-api`
3. Testar conectividade de porta local:
   `curl -i http://localhost:8000/healthz`

## 4. Causas Prováveis
* Exceção não tratada na inicialização do serviço (Startup Crash).
* Falha de resolução de dependências no boot (PostgreSQL ou Redis inatingíveis).
* Falha de memória no processo (OOM Kill).

## 5. Comandos Reais e Não Destrutivos
* Verificar uso de recursos no host:
  `free -h; df -h; uptime`
* Verificar conexões ativas na porta 8000:
  `netstat -tulpn | grep 8000`

## 6. Recuperação
1. Tentar reiniciar o serviço da API de forma graciosa:
   `docker compose restart govsec-core-api`
2. Caso persista falha de container, verificar variáveis de ambiente sem expor segredos:
   `docker inspect govsec-core-api --format '{{json .State}}'`

## 7. Validação Pós-Recuperação
1. Executar probe de Liveness:
   `curl -s http://localhost:8000/healthz`
2. Executar probe de Readiness:
   `curl -s http://localhost:8000/ready`
3. Confirmar retorno do scraping no Prometheus (`up == 1`).

## 8. Rollback
* Caso o problema decorra de um novo deploy de imagem, realizar rollback para a tag anterior:
  `docker compose pull govsec-core-api:previous && docker compose up -d govsec-core-api`

## 9. Evidências a Preservar
* Exportar os logs de erro completos antes do restart:
  `docker logs govsec-core-api > /tmp/govsec-core-api-crash.log`
* Preservar arquivo de dump de memória/stack trace.

## 10. Escalonamento
* Se não restabelecido em 15 minutos: escalonar para o Engenheiro Principal SRE da escala on-call.

## 11. Links Recomendados
* Dashboard Grafana Golden Signals: `http://localhost:3001/d/golden-signals`
* Prometheus Targets: `http://localhost:9090/targets`
