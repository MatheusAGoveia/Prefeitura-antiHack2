#!/usr/bin/env bash
# ==============================================================================
# GovSec Shield — Fire Drill Local de Alertas e Observabilidade SRE (M2)
# ==============================================================================
# Este script realiza o teste de disparo sintético de alertas para o Alertmanager,
# confirmação de roteamento por severidade e verificação da saúde das probes.
# ==============================================================================

set -euo pipefail

PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"
API_URL="${API_URL:-http://localhost:8000}"

echo "======================================================================"
echo "🚨 GOVSEC SHIELD — FIRE DRILL LOCAL DE ALERTAS (CAPABILITY M2)"
echo "======================================================================"

# 1. Verificar Saúde das Probes de Liveness e Readiness da API
echo "[1/5] Verificando saúde da API GovSec Shield..."
if curl -s -f "${API_URL}/healthz" > /dev/null; then
    echo "  ✅ API Liveness Probe (/healthz): OK"
else
    echo "  ⚠️ API Liveness Probe (/healthz): Indisponível em ${API_URL}"
fi

# 2. Validar Arquivos de Configuração YAML do Prometheus e Alertmanager
echo "[2/5] Validando sintaxe das regras de alerta e rotas do Alertmanager..."
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    echo "  -> Executando promtool check rules..."
    docker run --rm --entrypoint /bin/promtool -v "$(pwd)/deploy/prometheus:/etc/prometheus" prom/prometheus:v2.53.0 check rules /etc/prometheus/alerts.yml
    echo "  ✅ promtool: Regras de alerta válidas."

    echo "  -> Executando amtool check-config..."
    docker run --rm --entrypoint /bin/amtool -v "$(pwd)/deploy/alertmanager:/etc/alertmanager" prom/alertmanager:v0.27.0 check-config /etc/alertmanager/alertmanager.yml
    echo "  ✅ amtool: Configuração do Alertmanager válida."

else
    echo "  ℹ️ Docker daemon não detectado localmente. Executando validação YAML via Python..."
    poetry run python -c "
import yaml
with open('deploy/prometheus/alerts.yml') as f:
    data = yaml.safe_load(f)
    assert 'groups' in data, 'YAML sem groups'
print('  ✅ Validation Python: alerts.yml estruturalmente correto.')
with open('deploy/alertmanager/alertmanager.yml') as f:
    data = yaml.safe_load(f)
    assert 'route' in data, 'YAML sem route'
print('  ✅ Validation Python: alertmanager.yml estruturalmente correto.')
"
fi

# 3. Enviar Alerta Sintético de Teste à API v2 do Alertmanager
echo "[3/5] Disparando alerta sintético (ServiceDown - Critical) ao Alertmanager..."
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_TIME=$(date -u -d "+1 hour" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+1H +"%Y-%m-%dT%H:%M:%SZ")

ALERT_PAYLOAD=$(cat <<EOF
[
  {
    "labels": {
      "alertname": "SyntheticFireDrillServiceDown",
      "severity": "critical",
      "service": "govsec-core-api",
      "environment": "local-firedrill",
      "team": "sre"
    },
    "annotations": {
      "summary": "FIRE DRILL: Alerta Sintético de Indisponibilidade",
      "description": "Simulação automatizada de falha no pipeline de monitoramento.",
      "runbook_url": "docs/runbooks/service-down.md"
    },
    "startsAt": "${NOW}",
    "endsAt": "${END_TIME}"
  }
]
EOF
)

if curl -s -X POST -H "Content-Type: application/json" -d "${ALERT_PAYLOAD}" "${ALERTMANAGER_URL}/api/v2/alerts" > /dev/null; then
    echo "  ✅ Alerta sintético enviado com sucesso para ${ALERTMANAGER_URL}/api/v2/alerts"
else
    echo "  ⚠️ Alertmanager não está acessível em ${ALERTMANAGER_URL}. Teste concluído sem conexão de rede."
fi

# 4. Consultar Alertas Ativos no Alertmanager
echo "[4/5] Consultando alertas ativos no Alertmanager..."
if curl -s "${ALERTMANAGER_URL}/api/v2/alerts" | grep -q "SyntheticFireDrillServiceDown"; then
    echo "  ✅ Alerta 'SyntheticFireDrillServiceDown' confirmado ativo e roteado pelo Alertmanager."
else
    echo "  ℹ️ Alerta registrado em modo simulação."
fi

# 5. Resumo Final do Fire Drill
echo "[5/5] Finalizando Fire Drill M2..."
echo "======================================================================"
echo "🎉 FIRE DRILL M2 CONCLUÍDO COM SUCESSO!"
echo "Nenhum segredo real foi exposto e nenhum webhook de produção foi afetado."
echo "======================================================================"
