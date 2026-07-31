# Diagramas de Arquitetura C4 — GovSec Shield

Este documento especifica a arquitetura do **GovSec Shield** através do modelo C4 (Contexto, Contêineres e Componentes) utilizando sintaxe **Mermaid**.

---

## 1. Nível C1 — Diagrama de Contexto (System Context)

O Diagrama de Contexto ilustra o GovSec Shield no centro do ecossistema de segurança governamental, detalhando as interações com analistas de SOC, administradores municipais e sistemas externos integrados.

```mermaid
graph TD
    user_soc["👤 Analista SOC Municipal<br/>[Operador de Segurança]"]
    user_admin["👤 Administrador do Sistema<br/>[SysAdmin / SecAdmin]"]
    wazuh_collector["🖥️ Agentes de Telemetria<br/>[Wazuh / Zabbix / Firewalls]"]
    opa_engine["⚙️ OPA Policy Engine<br/>[Open Policy Agent - INV-005]"]
    external_misp["🌐 Threat Feeds Externos<br/>[MISP / AlienVault OTX]"]

    subgraph GovSecSystem ["🛡️ GovSec Shield — Security OS"]
        core_system["Plataforma Operacional de Segurança Governamental"]
    end

    user_soc -->|"Monitora alertas e mitiga incidentes (HTTPS)"| core_system
    user_admin -->|"Gerencia tenants, políticas e usuários (HTTPS)"| core_system
    wazuh_collector -->|"Envia logs e telemetria brutos (Syslog/REST/gRPC)"| core_system
    core_system -->|"Valida políticas e autorizações de comando (HTTP)"| opa_engine
    core_system -->|"Enriquece indicadores de ameaças IoC (REST)"| external_misp
```

---

## 2. Nível C2 — Diagrama de Contêineres (Containers Diagram)

O Diagrama de Contêineres descreve a topologia interna das aplicações, barramentos de mensageria e bancos de dados que compõem o GovSec Shield, atualizado com os containers reais em execução (M3.3).

```mermaid
graph TD
    subgraph FrontendLayer ["Layer 1: Frontend & Dashboard"]
        dashboard_web["🖥️ SOC Dashboard<br/>[Next.js 14 / React 18 / Tailwind CSS]<br/>Interface web interativa para operadores de SOC"]
    end

    subgraph ApiGatewayLayer ["Layer 2: API & Gateway"]
        fastapi_app["⚡ Core Platform API<br/>[Python 3.12 / FastAPI / Uvicorn]<br/>API RESTful assíncrona e endpoints de ingestão"]
    end

    subgraph WorkerLayer ["Layer 2b: Background Workers"]
        corr_worker["⚙️ Correlation Worker<br/>[CorrelationKafkaConsumer]<br/>Consumidor Kafka de SecurityEventReceivedEvent<br/>Aplica regras determinísticas e persiste incidentes"]
    end

    subgraph SecurityKernelLayer ["Layer 3: Security & Policies"]
        opa_container["🔒 OPA Engine<br/>[Open Policy Agent Container]<br/>Validador de políticas Rego (INV-005)"]
    end

    subgraph ObservabilityLayer ["Layer 3b: Observability Stack"]
        prometheus["📊 Prometheus<br/>[prom/prometheus:v2.53.0]<br/>Coleta métricas via /metrics (scrape autoritativo)"]
        grafana["📈 Grafana<br/>[grafana/grafana:11.1.0]<br/>Dashboard golden signals + incidentes abertos"]
        loki["📋 Loki<br/>[grafana/loki:3.1.0]<br/>Agregação de logs estruturados JSON"]
        tempo["🔍 Tempo<br/>[grafana/tempo:2.5.0]<br/>Rastreamento distribuído OpenTelemetry"]
        alertmanager["🔔 Alertmanager<br/>[prom/alertmanager:v0.27.0]<br/>Roteamento de alertas críticos"]
    end

    subgraph BrokerLayer ["Layer 4: Message Broker"]
        redpanda_broker["🚀 Redpanda Broker<br/>[C++ Kafka API Compatible]<br/>Barramento de eventos append-only de alta velocidade"]
    end

    subgraph StorageLayer ["Layer 5: Persistence & Cache"]
        postgres_db[("🐘 PostgreSQL 16 DB<br/>[PostgreSQL + RLS Enabled]<br/>Fonte de verdade para incidentes, evidências e métricas")]
        redis_cache[("⚡ Redis 7 Cache<br/>[In-Memory Cache]<br/>Cache de sessões JWT e Rate Limit")]
    end

    dashboard_web -->|"Consome API via REST / JSON (HTTPS)"| fastapi_app
    fastapi_app -->|"Valida escopo e autorização (HTTP)"| opa_container
    fastapi_app -->|"Publica SecurityEventReceivedEvent (Kafka Protocol)"| redpanda_broker
    fastapi_app -->|"Persiste entidades com RLS (AsyncPG)"| postgres_db
    fastapi_app -->|"Armazena sessões e limites (RESP)"| redis_cache
    fastapi_app -->|"Expõe GET /metrics (scrape autoritativo)"| prometheus
    corr_worker -->|"Consome SecurityEventReceivedEvent"| redpanda_broker
    corr_worker -->|"Persiste Incident + Evidence (transacional)"| postgres_db
    prometheus -->|"Scrape /metrics → govsec_open_incidents"| fastapi_app
    prometheus -->|"Dispara alertas (PromQL rules)"| alertmanager
    grafana -->|"Consulta métricas (PromQL)"| prometheus
    grafana -->|"Consulta logs (LogQL)"| loki
    grafana -->|"Consulta traces (TraceQL)"| tempo
```

---

## 4. Nível C3 — Componentes M3.3: Incident API & Correlation Engine

Detalha o subsistema de Incidentes e Correlação implementado na Sprint M3.3.

```mermaid
graph TD
    subgraph IncidentAPILayer ["src/core/interfaces/rest/"]
        inc_router["incident_routers.py<br/>GET /api/v1/incidents<br/>GET /api/v1/incidents/{id}<br/>PATCH /api/v1/incidents/{id}/status<br/>GET /api/v1/incidents/{id}/evidences<br/>GET /api/v1/incidents/{id}/history"]
    end

    subgraph MetricsLayer ["src/shared/observability/"]
        metrics_ep["metrics_endpoint_handler<br/>GET /metrics<br/>sync_open_incidents_gauge_from_db()<br/>HTTP 500 se PostgreSQL indisponível"]
        metrics_counters["Counters M3.3<br/>govsec_incidents_total<br/>govsec_incident_status_transitions_total<br/>govsec_incident_evidences_total<br/>govsec_open_incidents (Gauge)"]
    end

    subgraph CorrelationWorkerLayer ["src/core/infrastructure/messaging/"]
        consumer["CorrelationKafkaConsumer<br/>process_single_message()<br/>Consome SecurityEventReceivedEvent<br/>Idempotente por CorrelationKey"]
    end

    subgraph CorrelationEngineLayer ["src/core/domain/ (Domain Layer)"]
        engine["CorrelationEngine<br/>correlate(security_event)<br/>Aplica CorrelationRules tipadas"]
        rules["CorrelationRules<br/>R-INFRA-001 (InfrastructureRule)<br/>R-AUTH-001 (AuthenticationRule)<br/>SHA-256 CorrelationKey"]
    end

    subgraph RepositoriesLayer ["src/core/infrastructure/db/"]
        inc_repo["PostgresIncidentRepository<br/>save(), list(), get_by_id()<br/>count_open_by_severity()"]
        ev_repo["PostgresIncidentEvidenceRepository<br/>save(), list_by_incident()"]
        hist_repo["PostgresIncidentStatusHistoryRepository<br/>save(), list_by_incident()"]
        uow["PostgresCorrelationUnitOfWork<br/>__aenter__/__aexit__<br/>Transação atômica commit/rollback"]
    end

    inc_router -->|"Consulta/altera incidentes"| inc_repo
    inc_router -->|"Consulta evidências"| ev_repo
    inc_router -->|"Consulta histórico de status"| hist_repo
    metrics_ep -->|"count_open_by_severity()"| inc_repo
    metrics_ep -->|"atualiza"| metrics_counters
    consumer -->|"correlate()"| engine
    engine -->|"aplica"| rules
    engine -->|"persiste via"| uow
    uow -->|"save Incident"| inc_repo
    uow -->|"save Evidence"| ev_repo
```

