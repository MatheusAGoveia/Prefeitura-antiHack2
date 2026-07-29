# Runbook — HighMemoryUsage (Alto Uso de Memória no Host)

## 1. Impacto
* Risco de reinício abrupto por OOM Killer (Out Of Memory) nos contêineres Docker.
* Degradação geral de performance por swapping.
* Nível de severidade: **WARNING**.

## 2. Sintomas
* Métrica `system_memory_used_bytes > 2684354560` (2.5 GB) por 5 minutos contínuos.
* Alerta `HighMemoryUsage` em estado `FIRING`.

## 3. Diagnóstico Seguro
1. Verificar consumo de RAM por processo/contêiner no host:
   `docker stats --no-stream`
2. Verificar consumo de memória RAM do sistema operacional:
   `free -h -m`
3. Identificar os 5 maiores consumidores de memória:
   `ps aux --sort=-%mem | head -n 6`

## 4. Causas Prováveis
* Memory leak na aplicação ou bibliotecas assíncronas.
* Acúmulo de objetos na memória (ex: logs não descarregados ou cache ilimitado).
* Subdimensionamento de memória no servidor para a quantidade de contêineres ativos.

## 5. Comandos Reais e Não Destrutivos
* Verificar uso de swap:
  `swapon --show`

## 6. Recuperação
1. Identificar se o consumo excessivo é do processo Python/Uvicorn, Prometheus, Loki ou Tempo.
2. Se for um serviço específico de observabilidade (ex: Loki/Tempo), limitar memória no Docker Compose.
3. Se for o container da API com memory leak, efetuar restart gracioso:
   `docker compose restart govsec-core-api`

## 7. Validação Pós-Recuperação
1. Monitorar o indicador `system_memory_used_bytes` no Grafana.
2. Garantir que a RAM utilizada permaneça abaixo do limite de alerta (2.5 GB).

## 8. Rollback
* Reverter aumentos de retenção ou cargas em lote recentes.

## 9. Evidências a Preservar
* Saída do `docker stats` e mapa de memória do processo Python (`/proc/$PID/smaps`).

## 10. Escalonamento
* Escalonar para a equipe de Engenharia de Plataforma / Infraestrutura.

## 11. Links Recomendados
* Dashboard Grafana System Metrics: `http://localhost:3001/d/golden-signals`
