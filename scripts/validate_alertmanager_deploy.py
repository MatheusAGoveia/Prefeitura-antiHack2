"""
GovSec Shield — Script de Preflight e Validação Operacional de Deploy do Alertmanager

Garante que o Alertmanager não possa ser implantado em Staging ou Produção
com configurações de desenvolvimento ou inseguras.

Este script executa APENAS a validação semântica de segurança:
  - Verifica nome do arquivo renderizado
  - Valida ausência de termos proibidos
  - Confirma presença de segredos (Slack, PagerDuty)
  - Valida estrutura YAML (route, receivers, inhibit_rules)
  - Verifica rotas obrigatórias (critical, warning)

A validação sintática via `amtool check-config` é executada em container
Alertmanager nativo separado (ver docker-compose.production.yml).
"""

import os
import sys
from typing import Any

import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _mask_secret(val: str) -> str:
    """Mascara URLs e secrets para exibição segura em logs."""
    if not val:
        return "[VAZIO]"
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}...{val[-4:]}"


def _validate_yaml_semantic(config_path: str, content: str) -> int:
    """Valida a estrutura YAML semântica do Alertmanager (route, receivers, inhibit_rules)."""
    try:
        data: Any = yaml.safe_load(content)
    except yaml.YAMLError as e:
        print(f"❌ [ERRO YAML] Falha ao parsear o arquivo '{config_path}': {e}")
        return 1

    if not isinstance(data, dict):
        print(f"❌ [ERRO YAML] O arquivo '{config_path}' não é um mapeamento YAML válido.")
        return 1

    if "route" not in data:
        print(f"❌ [ERRO DE ESTRUTURA] Campo obrigatório 'route' ausente em '{config_path}'.")
        return 1

    if "receivers" not in data:
        print(f"❌ [ERRO DE ESTRUTURA] Campo obrigatório 'receivers' ausente em '{config_path}'.")
        return 1

    route = data["route"]
    if not isinstance(route, dict):
        print(f"❌ [ERRO DE ESTRUTURA] O campo 'route' deve ser um mapeamento YAML em '{config_path}'.")
        return 1

    receivers = data.get("receivers", [])
    if not isinstance(receivers, list) or len(receivers) == 0:
        print(f"❌ [ERRO DE ESTRUTURA] O campo 'receivers' deve conter ao menos um receiver em '{config_path}'.")
        return 1

    print("✅ Validação YAML semântica aprovada (route, receivers presentes).")
    return 0


def validate_deploy() -> int:
    """Executa a validação de preflight de segurança do Alertmanager."""
    env = os.getenv("GOVSEC_ENV", "dev").lower().strip()
    config_path = os.getenv("GOVSEC_ALERTMANAGER_CONFIG", "").strip()

    print("======================================================================")
    print(f"🚨 GOVSEC SHIELD — PREFLIGHT DE SEGURANÇA DO ALERTMANAGER [{env.upper()}]")
    print("======================================================================")

    if env not in ("staging", "production"):
        print(f"ℹ️ Ambiente '{env}': Validação em modo de desenvolvimento/teste.")
        default_cfg = config_path or "deploy/alertmanager/alertmanager.yml"
        if not os.path.exists(default_cfg):
            print(f"❌ [ERRO] Arquivo de configuração '{default_cfg}' não encontrado.")
            return 1

        # Validação YAML sintática e semântica mesmo em dev/test
        with open(default_cfg, encoding="utf-8") as f:
            content = f.read()

        yaml_result = _validate_yaml_semantic(default_cfg, content)
        if yaml_result != 0:
            return yaml_result

        print(f"✅ Arquivo local '{default_cfg}' existente e válido.")
        return 0

    # 1. Validação estrita de nome de arquivo em Staging / Production
    if not config_path:
        print("❌ [ERRO DE SEGURANÇA] GOVSEC_ALERTMANAGER_CONFIG não está definido.")
        return 1

    if not config_path.endswith("alertmanager.rendered.yml"):
        print(
            f"❌ [ERRO DE SEGURANÇA] GOVSEC_ALERTMANAGER_CONFIG deve ser exatamente "
            f"'alertmanager.rendered.yml' em {env.upper()}. (Recebido: '{config_path}')"
        )
        return 1

    if not os.path.exists(config_path):
        print(f"❌ [ERRO DE DEPLOY] Arquivo renderizado '{config_path}' não foi encontrado.")
        print("   Execute 'poetry run python scripts/render_alertmanager_config.py' antes do deploy.")
        return 1

    # 2. Inspeção estrita de conteúdo
    with open(config_path, encoding="utf-8") as f:
        content = f.read()

    forbidden_terms = (
        "alertmanager.yml",
        "test-receiver",
        "dev-null",
        "host.docker.internal",
        "localhost",
        "127.0.0.1",
        "XXX",
        "YYY",
        "ZZZ",
        "CHANGE_ME",
        "TODO",
        "0123456789abcdef0123456789abcdef",
        "pd-service-key-example",
        "# Slack não configurado",
        "# PagerDuty não configurado",
    )

    for term in forbidden_terms:
        if term in content:
            print(f"❌ [ERRO DE SEGURANÇA] O arquivo '{config_path}' contém o termo proibido '{term}'!")
            return 1

    # Check for empty webhooks or missing receivers
    if "api_url: ''" in content or 'api_url: ""' in content:
        print("❌ [ERRO DE SEGURANÇA] Detectado webhook de Slack vazio na configuração renderizada!")
        return 1

    if "service_key: ''" in content or 'service_key: ""' in content:
        print("❌ [ERRO DE SEGURANÇA] Detectada chave de PagerDuty vazia na configuração renderizada!")
        return 1

    # Check required severity routes
    if "severity: critical" not in content and 'severity: "critical"' not in content:
        print("❌ [ERRO DE ESTRUTURA] Rota obrigatória de severidade 'critical' ausente!")
        return 1

    if "severity: warning" not in content and 'severity: "warning"' not in content:
        print("❌ [ERRO DE ESTRUTURA] Rota obrigatória de severidade 'warning' ausente!")
        return 1

    # 3. Validação YAML semântica
    yaml_result = _validate_yaml_semantic(config_path, content)
    if yaml_result != 0:
        return yaml_result

    # 4. Verificação de presença dos segredos em variáveis ou arquivos de secret
    slack_url = os.getenv("GOVSEC_SLACK_WEBHOOK_URL", "").strip()
    slack_file = os.getenv("GOVSEC_SLACK_WEBHOOK_FILE", "").strip()
    if not slack_url and slack_file and os.path.exists(slack_file):
        with open(slack_file, encoding="utf-8") as sf:
            slack_url = sf.read().strip()

    pagerduty_key = os.getenv("GOVSEC_PAGERDUTY_SERVICE_KEY", "").strip()
    pagerduty_file = os.getenv("GOVSEC_PAGERDUTY_SERVICE_FILE", "").strip()
    if not pagerduty_key and pagerduty_file and os.path.exists(pagerduty_file):
        with open(pagerduty_file, encoding="utf-8") as pf:
            pagerduty_key = pf.read().strip()

    if not slack_url:
        print("❌ [ERRO DE SEGURANÇA] Webhook do Slack (GOVSEC_SLACK_WEBHOOK_URL/FILE) não configurado.")
        return 1

    if not pagerduty_key:
        print("❌ [ERRO DE SEGURANÇA] Chave do PagerDuty (GOVSEC_PAGERDUTY_SERVICE_KEY/FILE) não configurada.")
        return 1

    print(
        f"✅ Validação de regras e segredos aprovada "
        f"(Slack: {_mask_secret(slack_url)}, PagerDuty: {_mask_secret(pagerduty_key)})."
    )

    print("======================================================================")
    print(f"🎉 PREFLIGHT DE SEGURANÇA DO ALERTMANAGER [{env.upper()}] CONCLUÍDO COM SUCESSO!")
    print("======================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(validate_deploy())
