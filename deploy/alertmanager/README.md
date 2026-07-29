# GovSec Shield — Alertmanager Deployment & SRE Operation

## Visão Geral
Este repositório contém a configuração e documentação operacional do **Alertmanager (v0.27.0)** do GovSec Shield.

## Roteamento e Severidades

| Severidade | Receiver | Descrição |
| :--- | :--- | :--- |
| `critical` | `pagerduty-and-slack` | Incidentes graves exigindo acionamento imediato por on-call via PagerDuty e Slack. |
| `warning` | `slack-warnings` | Alertas operacionais exigindo atenção humana em horário comercial. |
| `info` | `dev-null` | Notificações informativas ou de desenvolvimento local. |

## Inibições Configuradas
* Quando o alerta raiz `ServiceDown` (crítico) está ativo para um serviço, os alertas secundários `HighLatency`, `NoLogsIngested` e `HighErrorRate` são inibidos automaticamente para reduzir ruído na equipe SOC/SRE.

## Validação Sintática Local

Você pode validar a sintaxe do arquivo de configuração executando:

```bash
docker run --rm -v ${PWD}/deploy/alertmanager:/etc/alertmanager prom/alertmanager:v0.27.0 amtool check-config /etc/alertmanager/alertmanager.yml
```
