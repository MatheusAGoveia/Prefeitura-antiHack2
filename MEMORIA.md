# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/core-platform`
- **Data da Última Atualização:** 2026-07-29T14:55:00Z
- **Responsável:** IA Assistente (Arquiteto Principal GovSec Shield)

---

## ✅ O que já foi implementado

### 1. Estrutura Base e Governança (2026-07-28)
- [x] Criação do `README.md` principal detalhando a visão do **Security Operating System (Security OS)**.
- [x] Criação da pasta de documentação técnica [`docs/`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs):
  - `M0.1_Vision_and_Bounded_Contexts.md`: Visão e Bounded Contexts.
  - `M0.3_Event_Storming_and_Flows.md`: Diagrama de Sequência Mermaid (Detecção -> Mitigação).
  - `M0.4_ER_Database_Model.md`: Modelo ER v5.4 do PostgreSQL com RLS e FKs compostas.
  - `M0.7_Canonical_Commands_Model.md`: Modelo Canônico de Commands (CQRS), envelopes JSON e invariantes.
  - `M0.8_Operational_Capability_Model.md`: Modelo de Maturidade por Capacidades (M0 a M9), KPIs, DoR/DoD.
  - `bounded-contexts.md`: Especificação técnica detalhada dos 9 Bounded Contexts e Context Mapping.
  - `architecture/c4-diagrams.md`: Diagramas de Arquitetura C4 (Níveis C1 Contexto, C2 Contêineres e C3 Componentes) em Mermaid.
  - `event-storming.md`: Matriz Command → Event por contexto, fluxos de mitigação e linha do tempo de eventos.
  - `er-diagram.md`: Modelo Entidade-Relacionamento completo em Mermaid (Tenants, Users, Assets, Incidents, AuditLogs), RLS e índices SQL.
  - `ADR-001`: Escolha do PostgreSQL como banco de dados principal (RLS, Lock Otimista, Table Inbox `PROCESSED_EVENTS`).
  - `ADR-002`: Adoção de CQRS e Event Sourcing Ready.
  - `ADR-003`: Implementação de Soft Delete para auditoria governamental (Zero Data Loss).
  - `ADR-004`: Escolha do Redpanda como broker de eventos (`Partition Key = AssetID`).

- [x] Configurações de ambiente, linters e automação: `.gitignore`, `pyproject.toml` (Poetry/Python 3.12), `.pre-commit-config.yaml`, `Makefile`, `docker/compose/docker-compose.yml` (PostgreSQL 16, Redpanda Kafka, Redis 7), `configs/dev/.env.example`.

### 2. Módulo Core Platform — `src/core/` (2026-07-28)
- [x] **Domínio (`src/core/domain/`):**
  - Entidade `Tenant` (`id`, `name`, `slug`, `status`, `created_at`, `updated_at`).
  - Interface `TenantRepository` (`save`, `get_by_id`, `get_by_slug`, `list`).
  - Eventos de Domínio Canônicos (M0.6): `TenantCreatedEvent`, `LogIngestedEvent`.
- [x] **Aplicação (`src/core/application/`):**
  - Commands Canônicos (M0.7): `CreateTenantCommand`, `IngestLogCommand`.
  - Handlers: `CreateTenantHandler`, `IngestLogHandler`.
  - DTOs e Queries: `CreateTenantDTO`, `TenantResponseDTO`, `IngestLogDTO`, `TenantQueryHandler`.
- [x] **Infraestrutura (`src/core/infrastructure/`):**
  - Banco de Dados (SQLAlchemy 2.0 + AsyncPG): `TenantModel`, `PostgresTenantRepository`, `UnitOfWork` assíncrono.
  - Mensageria: `EventBus` assíncrono (Redpanda/Kafka via `aiokafka` + fallback In-Memory) e `CommandBus`.
  - Security Kernel & RBAC: `SecurityKernel`, `JWTUtils` (`PyJWT`), `RBACManager` com roles (`viewer`, `analyst`, `engineer`, `security_admin`, `system_admin`).
  - Policy Engine (OPA Integration): `OPAClient` integrado ao `CommandBus` exigindo validação de políticas antes de cada Command (**INV-005**).
  - Migrações Alembic: `alembic.ini`, `env.py`, migração `0001_initial_tenants.py`.
- [x] **Interfaces (`src/core/interfaces/rest/` e `src/api/`):**
  - Rotas REST FastAPI: `POST /api/v1/tenants`, `GET /api/v1/tenants`, `POST /api/v1/logs`, `/healthz`, `/ready`.
  - CLI Admin: `src/cli/main.py` com o comando `govsec tenant create`.

### 3. Painel de Controle do Desenvolvimento (Dev Dashboard) (2026-07-28)
- [x] **Endpoint API (`/api/memoria`):** Parser dinâmico do `MEMORIA.md`, cálculo de progresso, leitura de git commit/branch e JSON formatado ([`dashboard_api.py`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/src/api/dashboard_api.py)).
- [x] **Interface Web Estática (`/dashboard`):** HTML + CSS escuro moderno + JS com auto-refresh (30s) e renderizador Markdown via `marked.js` ([`dashboard.html`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/src/api/static/dashboard.html)).
- [x] **Testes de Unidade:** Testes de integração direta do parser e rota do Dashboard ([`tests/unit/test_dashboard_api.py`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/tests/unit/test_dashboard_api.py)).

### 5. Dashboard MVP Next.js 14 (SOC Interface) (2026-07-28)
- [x] **Estrutura Next.js 14 (App Router):** Criado diretório `dashboard/` com React 18, TypeScript estrito, Tailwind CSS com tema SOC escuro e TanStack React Query.
- [x] **Habilitação de CORS no Backend:** Adicionado `CORSMiddleware` em `src/api/main.py` com suporte para `http://localhost:3000`.
- [x] **Módulos da Interface:**
  - **Visão Geral (`/`):** Indicadores de status da API (`/healthz` e `/ready`), estatísticas de tenants e progresso dinâmico lido de `MEMORIA.md`.
  - **Gestão de Tenants (`/tenants`):** Tabela em tempo real com busca por Nome/Slug/UUID e Modal de Criação de novos tenants.
  - **Central de Logs (`/logs`):** Tabela de auditoria de eventos e Simulador de Ingestão de Logs via `IngestLogCommand` enviando para o EventBus.
  - **ScopeSafety Protection (`/scope`):** Testador interativo do validador de sub-redes autorizadas da prefeitura (INV-005).
- [x] **Autenticação JWT:** Obtenção de token JWT via `/api/v1/auth/token` com envio automático nos cabeçalhos HTTP Bearer.

### 8. Sprint 0.3 — Event Bus & Mensageria (2026-07-28)
- [x] **Configuração Redpanda (`docker/compose/docker-compose.yml`):**
  - Serviço Redpanda configurado na porta `19092` com suporte aos tópicos `govsec-events` e `govsec-commands-dlq`.
- [x] **KafkaEventBus (`src/core/infrastructure/messaging/kafka_event_bus.py`):**
  - Implementado `KafkaEventBus` estendendo `EventBus` com suporte a `aiokafka`, garantia de idempotência (`is_duplicate`) e fallback transparente In-Memory.
- [x] **Middlewares do Command Bus (`src/core/infrastructure/messaging/command_bus.py`):**
  - Implementação dos 4 middlewares: `LoggingMiddleware`, `AuditMiddleware`, `RetryMiddleware` (até 3 tentativas) e `CircuitBreakerMiddleware` (`CircuitBreakerOpenError`).
- [x] **Dead Letter Queue (`src/core/infrastructure/messaging/dlq.py`):**
  - Persistência de mensagens mortas em falhas permanentes com suporte a repasse manual (`requeue_message`).
- [x] **Event Handlers (`src/core/interfaces/event_handlers/`):**
  - `TenantEventHandler` (`handle_tenant_created`) e `LogEventHandler` (`handle_log_ingested`).
- [x] **Suíte de Testes de Integração (`tests/integration/test_event_bus.py`):**
  - 5 testes de integração cobrindo mensageria Kafka, idempotência, middlewares, DLQ e Circuit Breaker.

### 9. Arquitetura de Observabilidade & SRE (`src/shared/observability/`) (2026-07-28)
- [x] **OpenTelemetry Tracing:**
  - Configurado `TracerProvider`, propagador W3C (`TraceContextTextMapPropagator`) e instrumentação automática FastAPI em `src/shared/observability/tracing.py`.
  - Instrumentação de Spans OpenTelemetry para cada **Command** e **Query** CQRS com atributos `command.name`, `query.name`, `tenant` e `user_id`.
- [x] **Prometheus Metrics Middleware:**
  - Implementado `PrometheusMetricsMiddleware` em `src/shared/observability/metrics.py` com contadores `http_requests_total` e histogramas `http_request_duration_seconds`.
  - Exposição de métricas no endpoint público `GET /metrics`.
- [x] **Logs Estruturados JSON (Grafana Loki):**
  - Implementado `GovSecJSONFormatter` em `src/shared/observability/logging.py` com campos `timestamp`, `level`, `logger`, `message`, `correlation_id`, `tenant`, `trace_id` e `span_id`.
- [x] **Health Checks Probes:**
  - Probe de Liveness (`GET /healthz`) e Probe de Readiness (`GET /ready`) com verificações ativas de conexão com PostgreSQL e Redpanda/Kafka em `src/shared/observability/health.py`.
- [x] **Dashboards Grafana Golden Signals:**
  - Dashboard em JSON `deploy/grafana/dashboards/golden_signals.json` cobrindo Latência (p50, p95, p99), Tráfego (RPS), Erros (4xx/5xx) e Saturação CQRS.
  - Configuração do Prometheus scrape target em `deploy/prometheus/prometheus.yml`.
- [x] **Suíte de Testes de Integração:**
  - [`test_observability.py`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/tests/integration/test_observability.py) validando métricas, health checks, logs JSON estruturados e tracing de Commands/Queries (totalizando 34/34 testes passados).

### 10. Sprint 2 — Finalização 100% (2026-07-28)
- [x] **Spans para Eventos de Domínio (`src/core/interfaces/event_handlers/`):**
  - `TenantEventHandler`: span `Event.TenantCreated` com atributos `event.type`, `event.id`, `tenant_id`.
  - `LogEventHandler`: span `Event.LogIngested` com atributos adicionais `log.source` e `log.payload_size`.
- [x] **Métricas Prometheus para Eventos (`src/shared/observability/metrics.py`):**
  - `DOMAIN_EVENTS_TOTAL` — Counter por `event_type`, `tenant`, `status`.
  - `DOMAIN_EVENT_HANDLER_DURATION_SECONDS` — Histogram de latência por `event_type`, `tenant`.
- [x] **Mascaramento de Dados Sensíveis (`src/shared/observability/sanitizer.py`):**
  - `DataMasker` com padrões regex para JWT/Bearer, CPF, cartão de crédito (PAN), e-mail e senhas.
  - Singleton `data_masker` integrado ao `GovSecJSONFormatter` (Zero PII Exposure nos logs).
  - 14 chaves sensíveis por nome (`password`, `token`, `api_key`, `secret`, etc.).
- [x] **Métricas de Sistema com psutil (`src/shared/observability/system_metrics.py`):**
  - `SystemMetricsCollector` expondo Gauges: `system_cpu_usage_percent`, `system_memory_used_bytes`, `system_memory_total_bytes`, `system_disk_used_bytes`, `system_disk_total_bytes`, `process_open_file_descriptors`.
  - `start_system_metrics_collector` — corrotina assíncrona com `asyncio.CancelledError` gracioso.
  - Integrado ao `lifespan` do FastAPI para inicialização e shutdown limpos.
- [x] **Middleware de Recovery (`src/api/middleware/recovery.py`):**
  - `RecoveryMiddleware` como middleware mais externo (outermost) na chain.
  - Captura qualquer `Exception` não tratada, loga traceback em JSON estruturado com `recovery_id`, `trace_id`, `span_id`.
  - Retorna HTTP 500 padronizado sem vazar stack trace ao cliente.
- [x] **Testes de Conclusão Sprint 2 (`tests/integration/test_sprint2_completion.py`):**
  - 22 testes adicionais cobrindo os 6 itens pendentes.
  - **Total acumulado: 56/56 testes aprovados (100% de sucesso).**

### 11. Stack de Monitoramento Prometheus + Grafana (2026-07-28)
- [x] **Docker Compose expandido (`docker/compose/docker-compose.yml`):**
  - Serviço `prometheus` (v2.53.0) na porta `9090` com retenção de 15 dias, `host.docker.internal` e `--web.enable-lifecycle`.
  - Serviço `grafana` (v11.1.0) na porta `3001` com usuário `admin / govsec` e `depends_on: prometheus`.
  - Volumes nomeados `prometheus_data` e `grafana_data` para persistência.
- [x] **Provisionamento Automático do Grafana (`deploy/grafana/provisioning/`):**
  - `datasources/prometheus.yml` — datasource Prometheus com UID fixo `govsec-prometheus`.
  - `dashboards/govsec.yml` — provider de dashboards apontando para `/var/lib/grafana/dashboards`.
- [x] **prometheus.yml expandido (`deploy/prometheus/prometheus.yml`):**
  - Self-monitoring do Prometheus (`job: prometheus`).
  - Scrape da API GovSec via `host.docker.internal:8000/metrics` com labels `service`, `version`, `environment`.
- [x] **Dashboard Grafana expandido (`deploy/grafana/dashboards/golden_signals.json`):**
  - Painel HTTP Golden Signals: Latência p50/p95/p99, Tráfego RPS, Erros 4xx/5xx, Saturação CQRS.
  - Painel Eventos de Domínio: volume `domain_events_total` + latência `domain_event_handler_duration_seconds`.
  - Painel Métricas de Sistema: Gauges CPU/RAM/Disco + série temporal de File Descriptors.

### 12. Stack Completa de Observabilidade — Loki + Tempo (2026-07-29)
- [x] **Grafana Loki (v3.1.0) — Agregação de Logs:**
  - Container `govsec-loki` na porta `3100` com schema TSDB v13, WAL e retenção de 168h.
  - Config: `deploy/loki/loki-config.yml` com `auth_enabled: false` (single-tenant dev).
  - Compactor com `delete_request_store: filesystem` para Loki 3.x.
- [x] **Grafana Tempo (v2.5.0) — Distributed Tracing:**
  - Container `govsec-tempo` nas portas `3200` (HTTP), `4317` (OTLP gRPC), `4318` (OTLP HTTP).
  - Config: `deploy/tempo/tempo-config.yml` com receivers OTLP gRPC/HTTP, retenção 72h.
  - Metrics Generator com `service-graphs` e `span-metrics` alimentando Prometheus via remote-write.
- [x] **Prometheus Remote Write Receiver:**
  - Flag `--web.enable-remote-write-receiver` adicionada para receber métricas do Tempo Metrics Generator.
- [x] **Datasources Grafana Expandidos:**
  - Prometheus: exemplar links para Tempo (`exemplarTraceIdDestinations`).
  - Loki (UID `govsec-loki`): `derivedFields` para correlação `trace_id` → Tempo.
  - Tempo (UID `govsec-tempo`): `tracesToLogsV2` → Loki, `tracesToMetrics` → Prometheus, `nodeGraph`, `serviceMap`.
- [x] **OTLP Exporter configurado:**
  - `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317` no `.env`.
  - Dependência `opentelemetry-exporter-otlp-proto-grpc` instalada.
  - O `tracing.py` já faz import condicional do `OTLPSpanExporter` — agora ativado.
- [x] **Validação End-to-End:**
  - Todos os 4 containers healthy: Prometheus, Loki, Tempo, Grafana.
  - Ambos os Prometheus targets UP: `prometheus` e `govsec-core-api`.
  - Todos os 3 datasources provisionados no Grafana: Prometheus, Loki, Tempo.
  - Métricas `http_requests_total` e `up` com dados reais da API.

### 13. Fechamento Capability M2 — Monitoramento, Alertas & Operação SRE (2026-07-29)
- [x] **Segurança e Validação de Ambiente:**
  - Configuração estrita em `src/core/infrastructure/config.py` validando `GOVSEC_ENV` (`dev`, `test`, `staging`, `production`), rejeitando segredos padrão ou curtos em `staging`/`production`.
  - Endpoint `POST /api/v1/auth/dev-token` restrito exclusivamente a `GOVSEC_ENV == "dev"`.
  - `OPAClient` com `mock_mode` forçado para `False` fora do ambiente de desenvolvimento.
- [x] **Persistência Operacional PostgreSQL:**
  - ORM Models `AuditLogModel` (`audit_logs`) e `AlertAcknowledgementModel` (`alert_acknowledgements`).
  - Migrações Alembic reversíveis `0002_create_audit_logs.py` e `0003_create_alert_acknowledgements.py`.
  - Repositórios `PostgresLogRepository` e `PostgresAlertAcknowledgementRepository` expostos via `UnitOfWork`.
- [x] **CQRS AcknowledgeAlertCommand & Eventos:**
  - Entidade `AlertAcknowledgement`, evento `AlertAcknowledgedEvent`, comando `AcknowledgeAlertCommand`, DTOs e handler `AcknowledgeAlertHandler` com idempotência e log de auditoria.
  - Endpoint REST `POST /api/v1/alerts/acknowledge` autorizando role `analyst` e auditando no `SecurityKernel`.
- [x] **Métricas Prometheus & Probes de Health:**
  - Gauges DB Pool (`govsec_db_pool_available_connections`, `govsec_db_pool_checked_out`), Gauges de infraestrutura (`govsec_event_bus_fallback_active`, `govsec_opa_available`) e contadores operacionais.
  - Probe de Readiness `/ready` degradando graciosa e determinantemente (503 Service Unavailable) se Kafka estiver em fallback ou OPA indisponível fora de dev.
- [x] **Stack Alertmanager & Regras Prometheus:**
  - Container `alertmanager` (v0.27.0) na porta 9093 adicionado ao Docker Compose.
  - `deploy/alertmanager/alertmanager.yml` com roteamento por severidade (`pagerduty-and-slack`, `slack-warnings`, `dev-null`) e inibição automática de alertas secundários quando `ServiceDown` está ativo.
  - `deploy/prometheus/alerts.yml` com as 6 regras mínimas da especificação + 6 regras internas do pipeline de observabilidade.
- [x] **Runbooks Operacionais SRE:**
  - 7 Runbooks markdown criados em `docs/runbooks/` (`service-down.md`, `high-latency.md`, `high-error-rate.md`, `db-connection-pool-exhausted.md`, `high-memory-usage.md`, `no-logs-ingested.md`, `alertmanager-down.md`) contendo as 11 seções padronizadas.
- [x] **Painéis Grafana M2:**
  - Dashboard `golden_signals.json` atualizado com a linha "🚨 Alertas & Operação SRE (Capability M2)" contendo status em tempo real de alertas ativos, pool de conexões DB, ingestão de logs e estado dos conectores.
- [x] **Fire Drill e Testes de Integração Automatizados:**
  - `scripts/test_alerts.py` (e `test-alerts.sh`) para validação sintática de YAML e envio de alerta sintético.
  - [`tests/integration/test_m2_monitoring.py`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/tests/integration/test_m2_monitoring.py) testando todas as regras e fluxos de M2.
  - **Resultado: 67/67 testes aprovados na suíte completa (100% de sucesso).**

---

## 🏗️ Decisões Arquiteturais Tomadas
1. **Domain First:** Nenhuma regra de negócio vazada para a infraestrutura ou API.
2. **Zero Trust & Security Kernel:** Negação de acesso por padrão; autorização RBAC verificada no Security Kernel.
3. **OPA Policy Gate (INV-005):** O `CommandBus` consulta obrigatoriamente o `OPAClient` antes de despachar qualquer comando para seu Handler.
4. **Resiliência do EventBus:** Implementado com `aiokafka` para produção e fallback transparente In-Memory para ambiente local/testes.
5. **Deduplicação e Idempotência:** `CorrelationKey` e tabela `PROCESSED_EVENTS` no PostgreSQL com restrição UNIQUE.
6. **Fail-Fast Database Engine:** O `UnitOfWork` não oculta erros de conexão nem tenta migrar silenciosamente para SQLite.
7. **Integração Frontend-Backend Decoplada:** O Dashboard consome diretamente os contratos REST expostos pela API FastAPI.
8. **Soft Delete de Tenants:** O comando de deleção preserva a integridade referencial alterando o status do tenant para `INACTIVE`, permitindo auditoria histórica.
9. **Observabilidade W3C & OpenTelemetry Native:** O Tracing propaga contexto W3C e vincula spans aos logs estruturados em JSON para correlação direta no Grafana (Loki/Tempo/Prometheus).
10. **Three Pillars of Observability:** Stack completa com Prometheus (métricas), Loki (logs) e Tempo (traces), com correlação bidirecional entre os três via Grafana datasource provisioning.
11. **Human-in-the-Loop Alert Acknowledgement (M2 Scope):** Alertas notificam operadores humanos sem acionar automações técnicas (mitigação/bloqueio automático é exclusivo de M3+). Acknowledgements são registrados como Commands auditáveis no PostgreSQL e geram eventos `AlertAcknowledgedEvent`.

---

## 📋 Próximos Passos (Pendentes)
- [ ] Abrir Pull Request da branch `feature/core-platform` para `main` e realizar merge.
- [ ] Iniciar planejamento da Capability M3 (Mitigação, Playbooks de Segurança e Integração SIEM/SOAR).
- [ ] Implementar o módulo de **Asset Discovery & Port Scanning** (`src/asset/`) utilizando o `BaseScanner` e `ScopeSafety` criados.
- [ ] Criar adaptadores da camada **Connectors (ACL)** para ingestão de alertas de terceiros (Wazuh, Zabbix).
- [ ] Implementar o **Risk Engine** (`src/risk/`) com cálculo determinístico de scores CVSS/EPSS via gRPC.

---

## 🧪 Resultados dos Testes
- **Data de Execução:** 2026-07-29T14:54:56Z
- **Comando:** `poetry run pytest --override-ini="addopts=" -v`
- **Resultado:** **67 passed** em 7.35s (100% de aprovação na suíte completa).
  - `tests/unit/`: 22 testes
  - `tests/integration/test_observability.py`: 6 testes
  - `tests/integration/test_event_bus.py`: 5 testes
  - `tests/integration/test_db_integration.py`: 1 teste
  - `tests/integration/test_sprint2_completion.py`: 22 testes
  - `tests/integration/test_m2_monitoring.py`: 11 testes (**NOVO M2**)

---

## 📁 Lista de Arquivos Criados/Modificados
- `src/core/infrastructure/config.py` **[MODIFICADO]**
- `.env.example` **[NOVO]**
- `configs/dev/.env.example` **[MODIFICADO]**
- `src/core/infrastructure/policies/opa_client.py` **[MODIFICADO]**
- `src/core/interfaces/rest/auth_routers.py` **[MODIFICADO]**
- `src/core/infrastructure/db/models.py` **[MODIFICADO]**
- `src/core/infrastructure/db/repositories.py` **[MODIFICADO]**
- `src/core/infrastructure/db/migrations/versions/0002_create_audit_logs.py` **[NOVO]**
- `src/core/infrastructure/db/migrations/versions/0003_create_alert_acknowledgements.py` **[NOVO]**
- `src/core/infrastructure/db/unit_of_work.py` **[MODIFICADO]**
- `src/core/domain/entities.py` **[MODIFICADO]**
- `src/core/domain/repositories.py` **[MODIFICADO]**
- `src/core/domain/events.py` **[MODIFICADO]**
- `src/core/application/commands.py` **[MODIFICADO]**
- `src/core/application/dto.py` **[MODIFICADO]**
- `src/core/application/handlers.py` **[MODIFICADO]**
- `src/core/interfaces/rest/dependencies.py` **[MODIFICADO]**
- `src/core/interfaces/rest/routers.py` **[MODIFICADO]**
- `src/shared/observability/metrics.py` **[MODIFICADO]**
- `src/shared/observability/health.py` **[MODIFICADO]**
- `docker/compose/docker-compose.yml` **[MODIFICADO — Alertmanager]**
- `deploy/alertmanager/alertmanager.yml` **[NOVO]**
- `deploy/alertmanager/README.md` **[NOVO]**
- `deploy/prometheus/prometheus.yml` **[MODIFICADO — Alertmanager target]**
- `deploy/prometheus/alerts.yml` **[NOVO]**
- `docs/runbooks/service-down.md` **[NOVO]**
- `docs/runbooks/high-latency.md` **[NOVO]**
- `docs/runbooks/high-error-rate.md` **[NOVO]**
- `docs/runbooks/db-connection-pool-exhausted.md` **[NOVO]**
- `docs/runbooks/high-memory-usage.md` **[NOVO]**
- `docs/runbooks/no-logs-ingested.md` **[NOVO]**
- `docs/runbooks/alertmanager-down.md` **[NOVO]**
- `deploy/grafana/dashboards/golden_signals.json` **[MODIFICADO — Painéis M2]**
- `scripts/test-alerts.sh` **[NOVO]**
- `scripts/test_alerts.py` **[NOVO]**
- `tests/integration/test_m2_monitoring.py` **[NOVO]**
- `MEMORIA.md` **[MODIFICADO]**

---

## 📝 Histórico de Atualizações Recentes
- **2026-07-28T18:10:00Z (IA Assistente):** Executada varredura e refatoração completa do projeto.
- **2026-07-28T19:18:00Z (IA Assistente):** Concluída a implementação completa do módulo de Observabilidade & SRE.
- **2026-07-28T19:42:00Z (IA Assistente):** Sprint 2 finalizada com 100% de cobertura.
- **2026-07-28T19:48:00Z (IA Assistente):** Stack de monitoramento Prometheus + Grafana adicionada ao Docker Compose.
- **2026-07-29T13:12:00Z (IA Assistente):** Stack completa de observabilidade implementada (Loki + Tempo).
- **2026-07-29T14:55:00Z (IA Assistente):** Fechamento completo da Capability M2 (Monitoramento, Alertas e Operação SRE). Implementados: (1) Validação rigorosa de ambiente em `config.py` e bloqueio de dev-tokens fora de dev; (2) Fail-Closed no OPA e probe `/ready` degradando com 503 se Kafka/OPA falharem fora de dev; (3) Persistência de `audit_logs` e `alert_acknowledgements` no PostgreSQL via UoW com migrações Alembic; (4) CQRS `AcknowledgeAlertCommand`, `AlertAcknowledgedEvent` e endpoint `/api/v1/alerts/acknowledge` autorizando `analyst`; (5) Gauges de pool DB e status de infraestrutura expostos no Prometheus; (6) Serviço Alertmanager no Docker Compose, `alertmanager.yml` com rotas e inibições; (7) `alerts.yml` com 6 alertas mínimos + 6 alertas internos de pipeline; (8) 7 Runbooks Markdown detalhados em `docs/runbooks/`; (9) Painéis SRE no Grafana `golden_signals.json`; (10) Fire drill script e suíte de testes de integração em `test_m2_monitoring.py`. **67/67 testes aprovados com 100% de sucesso**.
