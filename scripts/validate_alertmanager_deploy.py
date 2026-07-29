"""
GovSec Shield — Preflight e Validação Semântica Estrutural de Deploy do Alertmanager

Garante que o Alertmanager não possa ser implantado em Staging ou Produção
com configurações de desenvolvimento, incompletas ou inseguras.

Executa validação estrutural recursiva com parser YAML:
  - Presença obrigatória dos blocos 'route' e 'receivers'.
  - Validação de que TODOS os receivers referenciados em rotas (inclusive filhas) existem.
  - Rota 'severity: critical' encaminha para receiver com slack_configs e pagerduty_configs.
  - Rota 'severity: warning' encaminha para receiver com slack_configs.
  - Rejeição de placeholders, dev-null, URLs locais/falsas e segredos vazios.
  - Mensagens de erro objetivas sem exibição de segredos brutos.
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


def _collect_referenced_receivers(route_node: dict[str, Any], referenced: set[str], severity_routes: dict[str, str]) -> None:
    """Coleta recursivamente todos os receivers referenciados em rotas e mapeia severidades."""
    receiver = route_node.get("receiver")
    if receiver and isinstance(receiver, str):
        referenced.add(receiver)

    # Identificar mapeamento de severidade
    match_dict = route_node.get("match") or route_node.get("match_re") or {}
    if isinstance(match_dict, dict):
        severity = match_dict.get("severity")
        if severity and receiver and isinstance(receiver, str):
            severity_routes[str(severity).lower()] = receiver

    # Recursão em rotas filhas
    child_routes = route_node.get("routes", [])
    if isinstance(child_routes, list):
        for child in child_routes:
            if isinstance(child, dict):
                _collect_referenced_receivers(child, referenced, severity_routes)


def _validate_yaml_semantic(config_path: str, content: str, env: str) -> int:
    """Valida a estrutura YAML semântica e integridade de rotas/receivers."""
    try:
        data: Any = yaml.safe_load(content)
    except yaml.YAMLError as e:
        print(f"❌ [ERRO YAML] Falha ao parsear o arquivo '{config_path}': {e}")
        return 1

    if not isinstance(data, dict):
        print(f"❌ [ERRO YAML] O arquivo '{config_path}' não é um mapeamento YAML válido.")
        return 1

    # 1. Checagem de blocos obrigatórios
    if "route" not in data or not isinstance(data["route"], dict):
        print(f"❌ [ERRO ESTRUTURAL] Campo obrigatório 'route' ausente ou inválido em '{config_path}'.")
        return 1

    if "receivers" not in data or not isinstance(data["receivers"], list) or len(data["receivers"]) == 0:
        print(f"❌ [ERRO ESTRUTURAL] Campo obrigatório 'receivers' ausente ou vazio em '{config_path}'.")
        return 1

    receivers_list = data["receivers"]
    receiver_map: dict[str, dict[str, Any]] = {}
    for r in receivers_list:
        if isinstance(r, dict) and "name" in r and isinstance(r["name"], str):
            receiver_map[r["name"]] = r

    # 2. Coleta recursiva de receivers em rotas
    referenced_receivers: set[str] = set()
    severity_routes: dict[str, str] = {}
    _collect_referenced_receivers(data["route"], referenced_receivers, severity_routes)

    # 3. Validar se TODOS os receivers referenciados em rotas existem
    for ref in referenced_receivers:
        if ref not in receiver_map:
            print(f"❌ [ERRO INTEGRIDADE] A rota refere-se ao receiver '{ref}', mas ele NÃO está definido em 'receivers'!")
            return 1

    # 4. Validar proibições em Staging e Produção
    if env in ("staging", "production"):
        # Rejeitar dev-null em staging/produção
        if "dev-null" in receiver_map:
            print("❌ [ERRO DE SEGURANÇA] O receiver 'dev-null' é estritamente proibido em staging/produção!")
            return 1

        # Rejeitar placeholders, locais e fakes
        forbidden_terms = (
            "test-receiver",
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
                print(f"❌ [ERRO DE SEGURANÇA] O arquivo '{config_path}' contém o termo proibido ou placeholder '{term}'!")
                return 1

    # 5. Validação de Rota Critical
    critical_receiver_name = severity_routes.get("critical")
    if not critical_receiver_name and env in ("staging", "production"):
        print("❌ [ERRO DE ROTEAMENTO] Nenhuma rota definida para 'severity: critical'!")
        return 1

    if critical_receiver_name:
        critical_rcv = receiver_map.get(critical_receiver_name, {})
        has_slack = "slack_configs" in critical_rcv or "webhook_configs" in critical_rcv
        has_pd = "pagerduty_configs" in critical_rcv
        if env in ("staging", "production") and (not has_pd or not has_slack):
            print(
                f"❌ [ERRO DE ROTEAMENTO] O receiver crítico '{critical_receiver_name}' deve conter "
                f"obrigatoriamente 'pagerduty_configs' e 'slack_configs' em {env.upper()}!"
            )
            return 1

    # 6. Validação de Rota Warning
    warning_receiver_name = severity_routes.get("warning")
    if not warning_receiver_name and env in ("staging", "production"):
        print("❌ [ERRO DE ROTEAMENTO] Nenhuma rota definida para 'severity: warning'!")
        return 1

    if warning_receiver_name:
        warning_rcv = receiver_map.get(warning_receiver_name, {})
        has_slack = "slack_configs" in warning_rcv or "webhook_configs" in warning_rcv
        if env in ("staging", "production") and not has_slack:
            print(
                f"❌ [ERRO DE ROTEAMENTO] O receiver de warning '{warning_receiver_name}' deve conter "
                f"obrigatoriamente 'slack_configs' em {env.upper()}!"
            )
            return 1

    print("✅ Validação semântica de estrutura YAML (rotas, receivers e integridade) concluída com sucesso.")
    return 0


def validate_deploy() -> int:
    """Executa o preflight completo de segurança do Alertmanager."""
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

        with open(default_cfg, encoding="utf-8") as f:
            content = f.read()

        return _validate_yaml_semantic(default_cfg, content, env)

    # Staging / Production
    if not config_path:
        print("❌ [ERRO DE SEGURANÇA] GOVSEC_ALERTMANAGER_CONFIG não está definido.")
        return 1

    if not os.path.exists(config_path):
        print(f"❌ [ERRO DE DEPLOY] Arquivo renderizado '{config_path}' não foi encontrado.")
        return 1

    with open(config_path, encoding="utf-8") as f:
        content = f.read()

    # Validação semântica e estrutural do YAML
    yaml_result = _validate_yaml_semantic(config_path, content, env)
    if yaml_result != 0:
        return yaml_result

    # Checar se segredos estão presentes no ambiente ou arquivos
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
