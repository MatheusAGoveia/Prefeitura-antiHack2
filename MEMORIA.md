# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/m3.3-incident-center-api`
- **Data da Última Atualização:** 2026-07-31T15:28:00Z
- **Responsável:** IA Assistente (Arquiteto Principal GovSec Shield)
- **Status Atual:** SPRINT M3.3 (Central Operacional de Incidentes e Evidências) 100% CONCLUÍDA e HOMOLOGADA. Suíte completa expandida para 211 testes unitários e de integração aprovados sem ressalvas. Validação de qualidade de código (Ruff, Mypy, Bandit, Compileall, Git Diff, Docker e Test Alerts) 100% verde.

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

### 3. Homologação Estrita & Correção dos Bloqueadores M3.2 (2026-07-31)
- [x] **Versionamento do `poetry.lock`:** Removida a entrada de ignore em `.gitignore`, tornando o build Docker 100% determinístico e reproduzível.
- [x] **Declaração de Dependências Runtime (`psutil`):** Adicionado `psutil = "^5.9.0"` ao `pyproject.toml` e `requirements.txt`.
- [x] **Refinamento de Testes de Regressão:** Teste `test_run_loop_aborts_kafka_offset_commit_when_process_single_message_fails` criado validando com `assert_not_awaited()` que `consumer.commit` não é executado no loop quando o banco falha. Total de 205 testes aprovados.
- [x] **Healthcheck por Readiness File (`/tmp/correlation-worker.ready`):** Criado estritamente após a conexão bem-sucedida ao Redpanda/Kafka (`consumer.start()`) e removido em paradas/falhas.
- [x] **Limpeza de Qualidade (Git Diff Check):** Eliminadas linhas em branco excedentes ao final de `MEMORIA.md`, `pyproject.toml`, `requirements.txt` e `test_m3_2_correlation_integration.py`.

### 4. Sprint M3.3 — Central Operacional de Incidentes e Evidências (2026-07-31)
- [x] **Branch Dedicada:** `feature/m3.3-incident-center-api` criada a partir do commit mais recente da M3.2.
- [x] **DTOs de Aplicação (`src/core/application/dto.py`):** DTOs com payloads mascarados e modelos de listagem/paginação (`EvidenceResponseDTO`, `EvidenceListResponseDTO`, `IncidentHistoryResponseDTO`, `IncidentHistoryListResponseDTO`).
- [x] **Interfaces de Domínio (`src/core/domain/repositories.py`):** `IncidentRepository` expandido com suporte a filtros operacionais (`status`, `severity`, `created_from`, `created_to`) e ordenação segura; `IncidentEvidenceRepository` paginado; nova interface `IncidentStatusHistoryRepository`.
- [x] **Repositórios PostgreSQL (`src/core/infrastructure/db/repositories.py`):** `PostgresIncidentRepository` com SQL dinâmico e ordenação secundária determinística por ID; `PostgresIncidentEvidenceRepository` e `PostgresIncidentStatusHistoryRepository`.
- [x] **API REST Operacional (`src/core/interfaces/rest/incident_routers.py`):**
  - `GET /api/v1/incidents`: Filtros por status, severidade, janela de data, paginação (`skip`, `limit`) e ordenação (`sort_by`, `order`).
  - `GET /api/v1/incidents/{incident_id}/evidences`: Consulta de evidências com mascaramento sanitizado de payloads (`DataMasker`).
  - `GET /api/v1/incidents/{incident_id}/history`: Trilha de auditoria imutável de transições de status.
  - `PATCH /api/v1/incidents/{incident_id}/status`: Transição auditada com registro transacional em UoW.
  - Isolamento multi-tenant estrito: acesso cross-tenant retorna `HTTP 404 Not Found`.
- [x] **Métricas Prometheus de Observabilidade (`src/shared/observability/metrics.py`):** Métricas `GOVSEC_INCIDENTS_TOTAL`, `GOVSEC_INCIDENT_STATUS_TRANSITIONS_TOTAL` e `GOVSEC_INCIDENT_EVIDENCES_TOTAL` sem vazamento de labels sensíveis.
- [x] **Dashboard Grafana (`deploy/grafana/dashboards/golden_signals.json`):** Painel da Central Operacional de Incidentes (linha 50) com 4 novos gráficos.
- [x] **Suíte de Testes de Integração (`tests/integration/test_m3_3_incident_operations.py`):** 6 novos testes cobrindo filtros, ordenação estável, isolamento 404, payloads mascarados, histórico imutável e métricas Prometheus.

---

## 🏗️ Decisões Arquiteturais Tomadas (ADRs & Design)

| Data | Decisão | Justificativa |
| :--- | :--- | :--- |
| **2026-07-28** | PostgreSQL como banco principal | Suporte nativo a Row Level Security (RLS) para isolamento multi-tenant estrito por prefeitura. |
| **2026-07-28** | CQRS + Event-Driven | Desacoplamento entre escritas de alto volume (logs de auditoria) e leituras agregadas (dashboards SOC). |
| **2026-07-28** | Policy-as-Code via OPA | Invariante INV-005 exige que todo Command passe pela validação de políticas antes de alterar estado. |
| **2026-07-30** | ADR-005: Fundação do M3 | Arquitetura de correlação determinística com persistência transacional antes do Kafka e contratos de domínio timezone-aware UTC. |
| **2026-07-31** | Healthcheck por Readiness File | O worker só fica `healthy` após estabelecer a conexão real de grupo com o broker Redpanda, gravando o sinal no filesystem do container. |
| **2026-07-31** | Init Container `db-migrations` | Migrações do Alembic executam com sucesso antes da subida dos serviços dependentes de banco, prevenindo InFailedSQLTransactionError. |
| **2026-07-31** | Mascaramento Transparente DTO | Payloads brutos de evidências são obrigatoriamente sanitizados via `DataMasker` (`sanitize_payload`), impedindo o vazamento de segredos em respostas HTTP. |
| **2026-07-31** | Retorno 404 em Cross-Tenant | Consultas de incidentes/evidências de tenants não autorizados retornam estritamente HTTP 404 (em vez de 403) para não vazar a existência do recurso. |

---

## 📌 Registros Recentes & Próximos Passos
- **Sprint M3.3 Concluída & Homologada:** Todos os critérios de aceite cumpridos, 211 testes aprovados, Ruff 0 erros, Mypy 0 erros, Bandit 0 avisos, containers Docker `healthy`, Fire Drill M2 200 OK.
- **Próximos Passos (Início da próxima fase):**
  1. Desenvolver a desduplicação e recepção de webhooks do Alertmanager / Zabbix.
  2. Criar os fluxos de automação de resposta a incidentes.
  3. Desenvolver a interface web do Incident Center no frontend Next.js.
