"""
GovSec Shield — Renderizador Seguro de Configuração do Alertmanager (Staging/Production)
"""

import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


TEMPLATE_PATH = "deploy/alertmanager/alertmanager.production.yml.template"
OUTPUT_PATH = "deploy/alertmanager/alertmanager.rendered.yml"


def render_config() -> str:
    env = os.getenv("GOVSEC_ENV", "dev").lower().strip()
    slack_url = os.getenv("GOVSEC_SLACK_WEBHOOK_URL", "").strip()
    pagerduty_key = os.getenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "").strip()

    # Ler segredo de arquivo se especificado em segredo mounted (Kubernetes/Docker Secret)
    slack_file = os.getenv("GOVSEC_SLACK_WEBHOOK_FILE", "").strip()
    if slack_file and os.path.exists(slack_file):
        with open(slack_file, encoding="utf-8") as f:
            slack_url = f.read().strip()

    pagerduty_file = os.getenv("GOVSEC_PAGERDUTY_SERVICE_FILE", "").strip()
    if pagerduty_file and os.path.exists(pagerduty_file):
        with open(pagerduty_file, encoding="utf-8") as f:
            pagerduty_key = f.read().strip()

    if slack_url:
        slack_snippet = f"""slack_configs:
      - api_url: "{slack_url}"
        channel: "#govsec-alerts"
        send_resolved: true"""
    else:
        slack_snippet = "# Slack não configurado (sem credencial)"

    if pagerduty_key:
        pagerduty_snippet = f"""pagerduty_configs:
      - service_key: "{pagerduty_key}"
        send_resolved: true"""
    else:
        pagerduty_snippet = "# PagerDuty não configurado (sem credencial)"

    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        template = f.read()

    rendered = template.replace("{{SLACK_CONFIG}}", slack_snippet)
    rendered = rendered.replace("{{PAGERDUTY_CONFIG}}", pagerduty_snippet)

    # Validação de Segurança em Staging / Production:
    if env in ("staging", "production"):
        if not slack_url or not pagerduty_key:
            raise ValueError(
                f"🚨 [SECURITY ERROR] Ambiente '{env}' exige que Slack (GOVSEC_SLACK_WEBHOOK_URL/FILE) "
                f"e PagerDuty (GOVSEC_PAGERDUTY_SERVICE_KEY/FILE) estejam configurados!"
            )
        if "test-receiver" in rendered or "host.docker.internal" in rendered:
            raise ValueError(
                f"🚨 [SECURITY ERROR] Ambiente '{env}' proíbe o uso de 'test-receiver' ou endpoints locais no Alertmanager!"
            )



    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(rendered)

    print(f"✅ Configuração do Alertmanager [{env.upper()}] renderizada com sucesso em {OUTPUT_PATH}")
    return OUTPUT_PATH



if __name__ == "__main__":
    render_config()
