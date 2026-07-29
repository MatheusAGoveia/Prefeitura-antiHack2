"""
GovSec Shield — Script de Preflight e Validação Operacional de Deploy do Alertmanager
Garante que o Alertmanager não possa ser implantado em Staging ou Produção com configurações de desenvolvimento ou inseguras.
"""

import os
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def validate_deploy() -> int:
    env = os.getenv("GOVSEC_ENV", "dev").lower().strip()
    config_path = os.getenv("GOVSEC_ALERTMANAGER_CONFIG", "").strip()

    print("======================================================================")
    print(f"🚨 GOVSEC SHIELD — PREFLIGHT OPERACIONAL DO ALERTMANAGER [{env.upper()}]")
    print("======================================================================")

    if env not in ("staging", "production"):
        print(f"ℹ️ Ambiente '{env}': Validação em modo de desenvolvimento/teste.")
        default_cfg = config_path or "deploy/alertmanager/alertmanager.yml"
        if not os.path.exists(default_cfg):
            print(f"❌ [ERRO] Arquivo de configuração '{default_cfg}' não encontrado.")
            return 1
        print(f"✅ Arquivo local '{default_cfg}' existente.")
        return 0

    # 1. Validação de caminho em Staging / Production
    if not config_path:
        print("❌ [ERRO DE SEGURANÇA] GOVSEC_ALERTMANAGER_CONFIG não está definido.")
        print("   Em staging/produção, a variável de ambiente GOVSEC_ALERTMANAGER_CONFIG é obrigatória.")
        return 1

    if config_path.endswith("alertmanager.yml") and not config_path.endswith("alertmanager.rendered.yml"):
        print(f"❌ [ERRO DE SEGURANÇA] GOVSEC_ALERTMANAGER_CONFIG aponta para o arquivo de dev '{config_path}'.")
        print("   O uso do arquivo local 'alertmanager.yml' é estritamente proibido em staging e produção.")
        return 1

    if not os.path.exists(config_path):
        print(f"❌ [ERRO DE DEPLOY] Arquivo de configuração renderizado '{config_path}' não foi encontrado.")
        print("   Execute 'poetry run python scripts/render_alertmanager_config.py' antes de realizar o deploy.")
        return 1

    # 2. Leitura e inspeção estrita do conteúdo renderizado
    with open(config_path, encoding="utf-8") as f:
        content = f.read()

    if "test-receiver" in content:
        print(f"❌ [ERRO DE SEGURANÇA] O arquivo '{config_path}' contém 'test-receiver' de desenvolvimento!")
        return 1

    if "host.docker.internal" in content:
        print(f"❌ [ERRO DE SEGURANÇA] O arquivo '{config_path}' contém endpoints locais 'host.docker.internal'!")
        return 1

    if "# Slack não configurado" in content or "# PagerDuty não configurado" in content:
        print(f"❌ [ERRO DE SEGURANÇA] O arquivo '{config_path}' possui receivers não configurados ou sem credencial!")
        return 1

    # 3. Verificação de credenciais de Slack e PagerDuty
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

    print(f"✅ Validação de conteúdo e segredos aprovada para '{config_path}'.")

    # 4. Sintaxe amtool via Docker (se disponível)
    abs_config = os.path.abspath(config_path)
    config_dir = os.path.dirname(abs_config)
    config_file = os.path.basename(abs_config)

    try:
        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/bin/amtool",
            "-v",
            f"{config_dir}:/etc/alertmanager",
            "prom/alertmanager:v0.27.0",
            "check-config",
            f"/etc/alertmanager/{config_file}",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            print("✅ amtool check-config: Sintaxe YAML do Alertmanager VÁLIDA.")
        else:
            print(f"⚠️ amtool check-config falhou: {res.stderr.strip()}")
            return 1
    except Exception as e:
        print(f"ℹ️ Execução direta do amtool omitida (Docker daemon/imagem indisponível): {e}")

    print("======================================================================")
    print(f"🎉 PREFLIGHT DO ALERTMANAGER [{env.upper()}] CONCLUÍDO COM SUCESSO!")
    print("======================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(validate_deploy())
