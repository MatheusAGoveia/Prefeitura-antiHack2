# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/core-platform`
- **Data da Última Atualização:** 2026-07-28T19:42:00Z
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

---

## 📋 Próximos Passos (Pendentes)
- [ ] Abrir Pull Request da branch `feature/core-platform` para `main` e realizar merge.
- [ ] Implementar o módulo de **Asset Discovery & Port Scanning** (`src/asset/`) utilizando o `BaseScanner` e `ScopeSafety` criados.
- [ ] Criar adaptadores da camada **Connectors (ACL)** para ingestão de alertas de terceiros (Wazuh, Zabbix).
- [ ] Implementar o **Risk Engine** (`src/risk/`) com cálculo determinístico de scores CVSS/EPSS via gRPC.

---

## 🧪 Resultados dos Testes
- **Data de Execução:** 2026-07-28T19:42:00Z
- **Comando:** `poetry run pytest --override-ini="addopts=" -v`
- **Resultado:** **56 passed** em 2.06s (100% de aprovação na suíte completa).
  - `tests/unit/`: 22 testes
  - `tests/integration/test_observability.py`: 6 testes
  - `tests/integration/test_event_bus.py`: 5 testes
  - `tests/integration/test_db_integration.py`: 1 teste
  - `tests/integration/test_sprint2_completion.py`: 22 testes (**NOVO**)

---

## 📁 Lista de Arquivos Criados/Modificados
- `src/shared/observability/__init__.py`
- `src/shared/observability/tracing.py`
- `src/shared/observability/metrics.py`
- `src/shared/observability/logging.py`
- `src/shared/observability/health.py`
- `src/shared/observability/sanitizer.py` **[NOVO]**
- `src/shared/observability/system_metrics.py` **[NOVO]**
- `src/api/main.py`
- `src/api/middleware/auth.py`
- `src/api/middleware/recovery.py` **[NOVO]**
- `src/core/infrastructure/messaging/command_bus.py`
- `src/core/application/queries.py`
- `src/core/interfaces/event_handlers/tenant_event_handler.py`
- `src/core/interfaces/event_handlers/log_event_handler.py`
- `deploy/grafana/dashboards/golden_signals.json`
- `deploy/prometheus/prometheus.yml`
- `tests/integration/test_observability.py`
- `tests/integration/test_sprint2_completion.py` **[NOVO]**
- `MEMORIA.md`

---

## 📝 Histórico de Atualizações Recentes
- **2026-07-28T18:10:00Z (IA Assistente):** Executada varredura e refatoração completa do projeto.
- **2026-07-28T19:18:00Z (IA Assistente):** Concluída a implementação completa do módulo de Observabilidade & SRE (OpenTelemetry FastAPI Instrumentation, W3C Trace propagation, Prometheus Metrics Middleware, Structured JSON Logging Loki Compliant, CQRS Command & Query Tracing Spans, Health Checks /healthz e /ready, Dashboard Grafana Golden Signals e Suíte de Testes de Integração). 34/34 testes aprovados com 100% de sucesso.
- **2026-07-28T19:42:00Z (IA Assistente):** Sprint 2 finalizada com 100% de cobertura. Implementados: (1) Spans OTel em TenantEventHandler e LogEventHandler; (2) Métricas Prometheus `DOMAIN_EVENTS_TOTAL` e `DOMAIN_EVENT_HANDLER_DURATION_SECONDS`; (3) `DataMasker` com mascaramento de JWT, CPF, PAN, e-mail e senhas integrado ao `GovSecJSONFormatter`; (4) `SystemMetricsCollector` com psutil (CPU, RAM, Disco, FDs) integrado ao `lifespan` FastAPI; (5) `RecoveryMiddleware` como outermost middleware com logging estruturado do traceback; (6) 22 novos testes. Total: **56/56 testes aprovados** em 2.06s.
