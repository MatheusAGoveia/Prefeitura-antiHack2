# Runbook — AlertmanagerDown (Serviço Alertmanager Indisponível)

## 1. Impacto
* Falha no roteamento e notificação de alertas para PagerDuty e Slack.
* Risco de incidentes críticos não serem encaminhados ao time on-call.
* Nível de severidade: **CRITICAL**.

## 2. Sintomas
* Métrica `up{job="alertmanager"} == 0` por 1 minuto.
* Erros de notificação nos logs do Prometheus Exporter.

## 3. Diagnóstico Seguro
1. Verificar status do contêiner `govsec-alertmanager`:
   `docker ps --filter "name=govsec-alertmanager"`
2. Testar probe de saúde do Alertmanager:
   `curl -i http://localhost:9093/-/ready`
3. Inspecionar logs do Alertmanager:
   `docker logs --tail 100 govsec-alertmanager`

## 4. Causas Prováveis
* Erro de sintaxe no arquivo de configuração `alertmanager.yml`.
* Contêiner paralisado por falha de memória ou volume corrompido.
* Falha na porta `9093` ou conflito de binding no host.

## 5. Comandos Reais e Não Destrutivos
* Validar sintaxe da configuração sem reiniciar o contêiner:
  `docker run --rm -v ${PWD}/deploy/alertmanager:/etc/alertmanager prom/alertmanager:v0.27.0 amtool check-config /etc/alertmanager/alertmanager.yml`

## 6. Recuperação
1. Corrigir o arquivo `deploy/alertmanager/alertmanager.yml` caso haja erro de sintaxe.
2. Reiniciar o serviço via Docker Compose:
   `docker compose restart alertmanager`

## 7. Validação Pós-Recuperação
1. Executar probe de readiness:
   `curl -s http://localhost:9093/-/ready`
2. Confirmar que o Prometheus reestabeleceu a comunicação no target (`up == 1`).

## 8. Rollback
* Reverter o arquivo `alertmanager.yml` para a versão anterior funcional via Git:
  `git checkout HEAD~1 -- deploy/alertmanager/alertmanager.yml`

## 9. Evidências a Preservar
* Logs do contêiner `govsec-alertmanager` contendo a causa da falha.

## 10. Escalonamento
* Escalonar para o Líder da equipe de SRE / Observabilidade.

## 11. Links Recomendados
* Alertmanager Web UI: `http://localhost:9093`
* Prometheus Alerts UI: `http://localhost:9090/alerts`
