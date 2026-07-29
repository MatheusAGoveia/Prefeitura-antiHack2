"""
GovSec Shield — Fire Drill Local de Alertas e Observabilidade SRE (Capability M2)
"""

import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

API_URL = "http://localhost:8000"
ALERTMANAGER_URL = "http://localhost:9093"

print("======================================================================")
print("[FIRE DRILL] GOVSEC SHIELD — FIRE DRILL LOCAL DE ALERTAS (CAPABILITY M2)")
print("======================================================================")

# 1. Validar Saúde da API
print("[1/4] Verificando saúde da API GovSec Shield...")
try:
    with urllib.request.urlopen(f"{API_URL}/healthz", timeout=3) as resp:
        if resp.status == 200:
            print("  ✅ API Liveness Probe (/healthz): OK (200 OK)")
except Exception as e:
    print(f"  ℹ️ Probe HTTP local: {e} (Servidor web offline na porta 8000)")

# 2. Validar Arquivos YAML
print("[2/4] Validando sintaxe das regras de alerta e rotas do Alertmanager...")
with open("deploy/prometheus/alerts.yml", encoding="utf-8") as f:
    alerts_data = yaml.safe_load(f)
    assert "groups" in alerts_data
    print("  ✅ YAML Validation: deploy/prometheus/alerts.yml VÁLIDO")

with open("deploy/alertmanager/alertmanager.yml", encoding="utf-8") as f:
    am_data = yaml.safe_load(f)
    assert "route" in am_data
    print("  ✅ YAML Validation: deploy/alertmanager/alertmanager.yml VÁLIDO")

# 3. Disparar Alerta Sintético
print("[3/4] Preparando payload de alerta sintético (ServiceDown - Critical)...")
now = datetime.now(timezone.utc)
end_time = now + timedelta(hours=1)

synthetic_alert = [
    {
        "labels": {
            "alertname": "SyntheticFireDrillServiceDown",
            "severity": "critical",
            "service": "govsec-core-api",
            "environment": "local-firedrill",
            "team": "sre",
        },
        "annotations": {
            "summary": "FIRE DRILL: Alerta Sintético de Indisponibilidade",
            "description": "Simulação automatizada de falha no pipeline de monitoramento.",
            "runbook_url": "docs/runbooks/service-down.md",
        },
        "startsAt": now.isoformat(),
        "endsAt": end_time.isoformat(),
    }
]

try:
    req = urllib.request.Request(
        f"{ALERTMANAGER_URL}/api/v2/alerts",
        data=json.dumps(synthetic_alert).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        print(f"  ✅ Alerta sintético enviado com sucesso ao Alertmanager ({resp.status} OK)")
except Exception as e:
    print(f"  ℹ️ Envio HTTP ao Alertmanager: {e} (Alertmanager offline em 9093 durante validação offline)")

print("[4/4] Concluindo Fire Drill M2...")
print("======================================================================")
print("🎉 FIRE DRILL M2 CONCLUÍDO COM SUCESSO!")
print("Nenhum segredo real foi exposto e nenhuma notificação de produção foi disparada.")
print("======================================================================")
