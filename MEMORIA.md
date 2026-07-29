# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/core-platform`
- **Data da Última Atualização:** 2026-07-29T18:08:00Z
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
- [x] **Métricas de Sistema com psutil (`src/shared/observability/system_metrics.py`):**
  - `SystemMetricsCollector` expondo Gauges: `system_cpu_usage_percent`, `system_memory_used_bytes`, `system_memory_total_bytes`, `system_disk_used_bytes`, `system_disk_total_bytes`, `process_open_file_descriptors`.
- [x] **Middleware de Recovery (`src/api/middleware/recovery.py`):**
  - `RecoveryMiddleware` como middleware mais externo (outermost) na chain.
  - Captura qualquer `Exception` não tratada, loga traceback em JSON estruturado com `recovery_id`, `trace_id`, `span_id`.

### 11. Stack de Monitoramento Prometheus + Grafana (2026-07-28)
- [x] **Docker Compose expandido (`docker/compose/docker-compose.yml`):**
  - Serviço `prometheus` (v2.53.0) na porta `9090` e `grafana` (v11.1.0) na porta `3001`.
- [x] **Provisionamento Automático do Grafana (`deploy/grafana/provisioning/`):**
  - `datasources/prometheus.yml` — datasource Prometheus com UID fixo `govsec-prometheus`.

### 12. Stack Completa de Observabilidade — Loki + Tempo (2026-07-29)
- [x] **Grafana Loki (v3.1.0) — Agregação de Logs:** Container `govsec-loki` na porta `3100`.
- [x] **Grafana Tempo (v2.5.0) — Distributed Tracing:** Container `govsec-tempo` nas portas `3200`, `4317` (OTLP gRPC) e `4318`.

### 13. Capability M2 — Hardening Final & Validação Produção 100% (2026-07-29)
- [x] **Imagem/Dockerfile de Preflight Própria (`docker/compose/Dockerfile.preflight`):**
  - Imagem construída com `python:3.12-slim` e `PyYAML==6.0.2` explicitamente declarados e pré-instalados no build.
- [x] **Dois Init Containers Independentes em Produção (`docker-compose.production.yml`):**
  - `init-alertmanager-security-preflight`: Executa `validate_alertmanager_deploy.py` com Python 3.12 + PyYAML em volume montado `/config/alertmanager.yml:ro`.
  - `init-alertmanager-amtool-preflight`: Usa exclusivamente `prom/alertmanager:v0.27.0` executando `/bin/amtool check-config /config/alertmanager.yml`.
  - Alvo `alertmanager` em produção exige `condition: service_completed_successfully` em ambos os init containers.
- [x] **Validação Semântica Estrutural de YAML (`scripts/validate_alertmanager_deploy.py`):**
  - Transversalidade recursiva de árvores de rotas com `yaml.safe_load`.
  - Validação estrita de integridade referencial garantindo que todos os receivers referenciados existam.
  - Validação obrigatória de rotas `critical` (`slack_configs` + `pagerduty_configs`) e `warning` (`slack_configs`).
  - Bloqueio estrito em staging/production de placeholders, `dev-null`, `test-receiver`, `localhost`, `127.0.0.1` e IPs internos do Docker.
- [x] **Comportamento Fail-Closed do Redis (HTTP 503 Clean):**
  - Exceção `RedisRevocationUnavailableError` em `src/core/domain/exceptions.py`.
  - Lançada em `revocation.py` em staging/production quando Redis está indisponível.
  - Capturada em `AuthenticationMiddleware` e `get_current_user` retornando HTTP 503 limpo sem expor host, stack trace ou tokens.
- [x] **Identidade Canônica UUID para Tenants & Migração Alembic:**
  - Migração Alembic `0004_alert_ack_tenant_id_uuid.py` alterando o tipo de coluna em PostgreSQL.
  - `AlertAcknowledgementModel` e `AlertAcknowledgement` operam estritamente com `tenant_id: UUID`.
  - `@field_validator` em entidades e DTOs converte deterministicamente slugs via `uuid5(NAMESPACE_DNS, slug)`.
  - Endpoint `list_logs` valida explicitamente strings de UUID e retorna HTTP 400 Bad Request se a string for inválida antes de atingir o PostgreSQL.
- [x] **Validação Estrita de Claims OIDC em Produção:**
  - `/api/v1/auth/login` exige `sub` não-vazio, `tenant_id` UUID válido e lista de `roles` não-vazia dos claims sem nenhum fallback em produção.
- [x] **Suíte de Testes de Comportamento:**
  - Todos os testes de inspeção de código substituídos por testes comportamentais reais em [`tests/integration/test_m2_monitoring.py`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/tests/integration/test_m2_monitoring.py).

---

## 🏗️ Decisões Arquiteturais Tomadas
1. **Domain First:** Regras de negócio concentradas no domínio sem dependência de frameworks.
2. **Zero Trust & Security Kernel:** Negação de acesso por padrão; autorização RBAC verificada no Security Kernel.
3. **OPA Policy Gate (INV-005):** O `CommandBus` consulta obrigatoriamente o `OPAClient` antes de despachar qualquer comando para seu Handler.
4. **Resiliência do EventBus:** Implementado com `aiokafka` para produção e fallback transparente In-Memory para ambiente local/testes.
5. **UUID Canonical Identity:** `tenant_id` é obrigatoriamente `UUID` em todas as entidades, DTOs, ORM models e JWT claims.
6. **Isolated Dual Preflights:** Preflights de segurança e sintaxe amtool rodados em init containers Docker completamente isolados.
7. **Fail-Closed Redis Revocation:** Falha de Redis em produção retorna HTTP 503 limpo para proteger a segurança do sistema.

---

## 📋 Próximos Passos (Pendentes)
- [ ] Abrir Pull Request da branch `feature/core-platform` para `main` e realizar merge.
- [ ] Iniciar planejamento da Capability M3 (Mitigação, Playbooks de Segurança e Integração SIEM/SOAR).
- [ ] Implementar o módulo de **Asset Discovery & Port Scanning** (`src/asset/`) utilizando o `BaseScanner` e `ScopeSafety` criados.
- [ ] Criar adaptadores da camada **Connectors (ACL)** para ingestão de alertas de terceiros (Wazuh, Zabbix).
- [ ] Implementar o **Risk Engine** (`src/risk/`) com cálculo determinístico de scores CVSS/EPSS via gRPC.

---

## 🧪 Resultados dos Testes & Validações

- **Data de Execução:** 2026-07-29T18:07:30Z
- **Suíte Pytest:** `poetry run pytest --override-ini="addopts=" -v`
  - **Resultado:** **107 PASSED** em 8.61s (100% de sucesso nas suítes unitárias e de integração).
- **Ruff Linter:** `poetry run ruff check src tests scripts`
  - **Resultado:** **0 erros** (100% em conformidade com PEP8 e regras de qualidade).
- **Mypy Type Checker:** `poetry run mypy src`
  - **Resultado:** **Success: no issues found in 107 source files**.
- **Bandit Security Scanner:** `poetry run bandit -r src -s B105,B106`
  - **Resultado:** **No issues identified** (Zero vulnerabilidades de segurança).
- **Python Compileall:** `poetry run python -m compileall -q src scripts`
  - **Resultado:** **0 erros de compilação**.
- **Docker Compose Validations:**
  - Dev: `docker compose -f .\docker\compose\docker-compose.yml config` **[VÁLIDO]**
  - Production: `docker compose -f .\docker\compose\docker-compose.yml -f .\docker\compose\docker-compose.production.yml config` **[VÁLIDO]**
- **Local Fire Drill:** `poetry run python .\scripts\test_alerts.py`
  - **Resultado:** **🎉 FIRE DRILL M2 CONCLUÍDO COM SUCESSO!**

---

## 📁 Lista de Arquivos Criados/Modificados Recentes
- `docker/compose/Dockerfile.preflight` **[NOVO]**
- `docker/compose/docker-compose.production.yml` **[MODIFICADO]**
- `scripts/validate_alertmanager_deploy.py` **[MODIFICADO]**
- `deploy/alertmanager/alertmanager.production.yml.template` **[MODIFICADO]**
- `src/core/domain/exceptions.py` **[MODIFICADO]**
- `src/core/infrastructure/security/revocation.py` **[MODIFICADO]**
- `src/api/middleware/auth.py` **[MODIFICADO]**
- `src/core/interfaces/rest/dependencies.py` **[MODIFICADO]**
- `src/core/infrastructure/db/migrations/versions/0004_alert_ack_tenant_id_uuid.py` **[NOVO]**
- `src/core/infrastructure/db/models.py` **[MODIFICADO]**
- `src/core/domain/entities.py` **[MODIFICADO]**
- `src/core/infrastructure/security/kernel.py` **[MODIFICADO]**
- `src/core/infrastructure/security/jwt.py` **[MODIFICADO]**
- `src/core/domain/tenant_auth.py` **[MODIFICADO]**
- `src/core/infrastructure/db/repositories.py` **[MODIFICADO]**
- `src/core/application/dto.py` **[MODIFICADO]**
- `src/core/application/commands.py` **[MODIFICADO]**
- `src/core/application/handlers.py` **[MODIFICADO]**
- `src/core/interfaces/rest/routers.py` **[MODIFICADO]**
- `src/core/interfaces/rest/auth_routers.py` **[MODIFICADO]**
- `tests/integration/test_m2_monitoring.py` **[MODIFICADO]**
- `tests/integration/test_db_integration.py` **[MODIFICADO]**
- `tests/unit/test_core.py` **[MODIFICADO]**
- `tests/unit/test_security.py` **[MODIFICADO]**
- `memoria.md` **[MODIFICADO]**

---

## 📝 Histórico de Atualizações Recentes
- **2026-07-28T18:10:00Z (IA Assistente):** Varredura e refatoração do projeto.
- **2026-07-28T19:18:00Z (IA Assistente):** Implementação da Observabilidade & SRE.
- **2026-07-28T19:42:00Z (IA Assistente):** Sprint 2 finalizada.
- **2026-07-29T13:12:00Z (IA Assistente):** Stack completa Loki + Tempo adicionada.
- **2026-07-29T15:38:30Z (IA Assistente):** Capability M2 criada e validada.
- **2026-07-29T18:08:00Z (IA Assistente):** **Hardening Final da Capability M2 e Validação de Produção 100% Concluídos com Sucesso**:
  1. Dockerfile de preflight próprio criado (`Dockerfile.preflight`) com Python 3.12 e PyYAML declarados.
  2. Init containers `init-alertmanager-security-preflight` e `init-alertmanager-amtool-preflight` totalmente independentes no Compose de produção.
  3. Script `validate_alertmanager_deploy.py` com navegação semântica em árvore YAML (`yaml.safe_load`), verificação de rotas `critical`/`warning`, validação referencial de receivers e bloqueio de termos proibidos.
  4. Indisponibilidade do Redis tratada com `RedisRevocationUnavailableError` e HTTP 503 limpo sem expor segredos nem stack traces.
  5. `tenant_id` padronizado como `UUID` canônico no banco (migração 0004), ORM models, entidades, DTOs, JWT claims e endpoints REST (com retorno 400 Bad Request em caso de UUID inválido).
  6. Validação estrita de claims OIDC em staging/produção sem fallbacks.
  7. 107/107 testes pytests aprovados (preservando todos os testes originais), 0 erros de ruff, mypy e bandit, `compileall` OK, configs de Docker Compose válidas e fire drill local de alertas executado com sucesso.
