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

## Seleção de Configuração por Ambiente

| Ambiente | Arquivo Utilizado | Mecanismo & Descrição |
| :--- | :--- | :--- |
| `dev` / `test` | `deploy/alertmanager/alertmanager.yml` | Configuração local de desenvolvimento com receiver `test-receiver` apontando para o mock local HTTP. |
| `staging` / `production` | `deploy/alertmanager/alertmanager.rendered.yml` | Gerado pelo script `scripts/render_alertmanager_config.py` a partir do template `alertmanager.production.yml.template`. O script valida que **é estritamente proibido** utilizar `test-receiver` ou endpoints locais em Staging/Production. |

### Como Renderizar para Staging / Production:

1. Configurar as variáveis de ambiente ou arquivos de segredo:
   ```bash
   export GOVSEC_ENV=production
   export GOVSEC_ALERTMANAGER_CONFIG=deploy/alertmanager/alertmanager.rendered.yml
   export GOVSEC_SLACK_WEBHOOK_FILE=/var/run/secrets/slack_webhook
   export GOVSEC_PAGERDUTY_SERVICE_FILE=/var/run/secrets/pagerduty_key
   ```
2. Executar o script renderizador seguro:
   ```bash
   poetry run python scripts/render_alertmanager_config.py
   ```
3. O arquivo `deploy/alertmanager/alertmanager.rendered.yml` será gerado com credenciais seguras e mantido fora do controle de versão via `.gitignore`. O startup da aplicação em `staging`/`production` exige `GOVSEC_ALERTMANAGER_CONFIG` apontando para o arquivo renderizado válido e rejeita o uso do arquivo local `alertmanager.yml`.


## Validação Sintática Local

Você pode validar a sintaxe do arquivo de configuração executando:

```bash
docker run --rm --entrypoint /bin/amtool -v ${PWD}/deploy/alertmanager:/etc/alertmanager prom/alertmanager:v0.27.0 check-config /etc/alertmanager/alertmanager.yml
```

