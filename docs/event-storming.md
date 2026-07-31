# Event Storming & Diagrama de Fluxos — GovSec Shield

Este documento mapeia o **Event Storming** do GovSec Shield, estabelecendo a relação entre os **Commands** (intenções de escrita), **Events** (fatos de domínio imutáveis), seus respectivos Bounded Contexts, fluxos operacionais de mitigação e correlação por `CorrelationID` e `TenantID`.

---

## 1. Tabela Matriz: Commands → Events por Bounded Context

| Bounded Context | Command (Intenção de Escrita) | Command Payload / Invariante | Evento Produzido (Fato Imutável) | Tópico Redpanda/Kafka |
|---|---|---|---|---|
| **Core Platform** | `CreateTenantCommand` | `name`, `slug` (único) | `TenantCreatedEvent` | `govsec.core.tenant-created` |
| **Core Platform** | `UpdateTenantCommand` | `tenant_id`, `name`, `status` | `TenantUpdatedEvent` | `govsec.core.tenant-updated` |
| **Core Platform** | `DeleteTenantCommand` | `tenant_id` (Soft Delete) | `TenantDeletedEvent` | `govsec.core.tenant-deleted` |
| **Core Platform** | `IngestLogCommand` | `source`, `raw_data`, `tenant_id` | `LogIngestedEvent` | `govsec.core.log-ingested` |
| **Security & Auth** | `AuthenticateUserCommand` | `username`, `password_hash` | `UserAuthenticatedEvent` | `govsec.security.auth-success` |
| **Security & Auth** | `CheckScopeCommand` | `target_ip` (Whitelist Check) | `ScopeCheckCompletedEvent` | `govsec.security.scope-checked` |
| **Asset Management** | `DiscoverAssetCommand` | `ip_address`, `hostname`, `type` | `AssetDiscoveredEvent` | `govsec.asset.discovered` |
| **Asset Management** | `ScanPortsCommand` | `target_cidr`, `ports_range` | `PortScanCompletedEvent` | `govsec.asset.scan-completed` |
| **Risk Engine** | `CalculateAssetRiskCommand` | `asset_id`, `cve_id`, `cvss_score` | `AssetRiskCalculatedEvent` | `govsec.risk.calculated` |
| **Incident Response** | `CreateIncidentCommand` | `asset_id`, `severity`, `details` | `IncidentCreatedEvent` | `govsec.incident.created` |
| **Incident Response** ✅ M3.2 | `ChangeIncidentStatusCommand` | `incident_id`, `to_status`, `actor_id`, `reason` | `IncidentStatusChangedEvent` | `govsec.incident.status-changed` |
| **Incident Response** ✅ M3.2 | `LinkEvidenceCommand` | `incident_id`, `security_event_id`, `rule_id` | `EvidenceLinkedEvent` | `govsec.incident.evidence-linked` |
| **Incident Response** | `ExecutePlaybookCommand` | `incident_id`, `playbook_name` | `PlaybookExecutedEvent` | `govsec.incident.playbook-executed` |
| **Correlation Engine** ✅ M3.2 | (Consumidor Kafka) `SecurityEventReceivedEvent` | `tenant_id`, `security_event_id` | `IncidentCorrelatedEvent` \| `EvidenceLinkedEvent` | `govsec.correlation.security-events` |
| **System Governance** | `RecordAuditLogCommand` | `actor_id`, `action`, `resource` | `AuditRecordCreatedEvent` | `govsec.system.audit-recorded` |

---

## 2. Fluxos Principais de Eventos

### Fluxo Operacional A: Ingestão de Alertas de Segurança → Análise de Risco → Mitigação Automática

```mermaid
sequenceDiagram
    autonumber
    participant Wazuh as 🖥️ Wazuh Agent / Collector
    participant API as ⚡ Core Platform API
    participant OPA as 🔒 OPA Engine (INV-005)
    participant CB as 🚌 CommandBus
    participant EB as 🚀 EventBus (Redpanda)
    participant Risk as 🧮 Risk Engine
    participant Inc as 🚨 Incident Response
    participant Audit as 📜 System Audit

    Wazuh->>API: POST /api/v1/logs (IngestLogDTO)
    API->>CB: IngestLogCommand(source, raw_data, tenant_id)
    CB->>OPA: Validar permissão do Command (INV-005)
    OPA-->>CB: Policy Decision: ALLOWED
    CB->>EB: Publicar LogIngestedEvent
    
    par Ingestão Assíncrona
        EB->>Risk: Consumir LogIngestedEvent
        Risk->>Risk: Avaliar Severidade CVSS/EPSS (Score > 8.5)
        Risk->>EB: Publicar CriticalRiskThresholdExceededEvent
    and Auditoria Legal
        EB->>Audit: Registra AuditRecordCreatedEvent no PostgreSQL
    end

    EB->>Inc: Consumir CriticalRiskThresholdExceededEvent
    Inc->>Inc: Criar Incident com status OPEN
    Inc->>EB: Publicar IncidentCreatedEvent
    Inc->>Inc: Disparar Playbook de Mitigação (Bloqueio de IP)
    Inc->>EB: Publicar PlaybookExecutedEvent
```

---

## 3. Fluxo Operacional B: Correlação Determinística de Eventos → Incidente Aberto (M3.2 / M3.3) ✅

```mermaid
sequenceDiagram
    autonumber
    participant Collector as 🖥️ Collector (Wazuh/Syslog)
    participant API as ⚡ Core Platform API (FastAPI)
    participant Broker as 🚀 Redpanda (Kafka Protocol)
    participant Worker as ⚙️ CorrelationKafkaConsumer (Worker)
    participant Engine as 🧮 CorrelationEngine (Domain)
    participant PG as 🐘 PostgreSQL (Fonte de Verdade)
    participant Prom as 📊 Prometheus (/metrics)

    Collector->>API: POST /api/v1/logs (SecurityEvent)
    API->>PG: Persiste SecurityEventModel (transactional outbox)
    API->>Broker: Publica SecurityEventReceivedEvent (tenant_id, security_event_id)

    Broker->>Worker: process_single_message(SecurityEventReceivedEvent)
    Worker->>Engine: correlate(security_event)
    Engine->>Engine: Aplica regras tipadas (R-INFRA-001, R-AUTH-001...)
    Engine->>Engine: Gera CorrelationKey SHA-256 (tenant, rule_id, version, time_window)

    alt Incidente novo (CorrelationKey não existe)
        Engine->>PG: Persiste Incident(status=OPEN) + IncidentEvidence
        Worker->>Worker: safe_record_incident_evidence_added(rule_id)
        Worker-->>Broker: ACK (offset confirmado)
    else Replay / Incidente já existente (idempotência)
        Engine->>PG: Lê incidente existente, NÃO cria duplicata
        Worker-->>Broker: ACK (sem alteração de estado ou métricas)
    end

    Prom->>API: GET /metrics (scrape autoritativo)
    API->>PG: sync_open_incidents_gauge_from_db() → count_open_by_severity()
    alt PostgreSQL disponível
        PG-->>API: {high: 1, critical: 0, ...}
        API-->>Prom: HTTP 200 + govsec_open_incidents{severity="high"} 1.0
    else PostgreSQL indisponível
        PG-->>API: SQLAlchemyError
        API-->>Prom: HTTP 500 (up=0 — scrape falhou, sem dados stale)
    end
```

---

## 4. Envelope Canônico de Evento e Correlação de Dados (M0.7)

Todo evento emitido na infraestrutura Redpanda Kafka obedece ao seguinte envelope JSON unificado:

```json
{
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "event_name": "LogIngestedEvent",
  "version": "1.0.0",
  "tenant_id": "b3e04135-2633-4f91-[#tenant]-85a5e3860000",
  "correlation_id": "corr-8f921a-4122-8902a",
  "timestamp": "2026-07-28T18:45:00.000Z",
  "partition_key": "asset-betim-saude-01",
  "payload": {
    "source": "wazuh-agent-01",
    "raw_data": "AUTHENTICATION_FAILED src_ip=185.220.101.5",
    "severity": "HIGH"
  }
}
```

---

## 4. Grafo de Relações de Eventos (Event Lineage Graph)

```mermaid
graph LR
    LogIngested[LogIngestedEvent] -->|Dispara análise| RiskCalc[AssetRiskCalculatedEvent]
    RiskCalc -->|Se Score > 8.5| CriticalRisk[CriticalRiskThresholdExceededEvent]
    CriticalRisk -->|Abre Chamado| IncidentCreated[IncidentCreatedEvent]
    IncidentCreated -->|Dispara Automação| PlaybookExec[PlaybookExecutedEvent]
    PlaybookExec -->|Conclui Contenção| IncidentMitigated[IncidentMitigatedEvent]
    
    LogIngested -->|Audit Trail| AuditRecord[AuditRecordCreatedEvent]
    IncidentCreated -->|Audit Trail| AuditRecord
    PlaybookExec -->|Audit Trail| AuditRecord
```
