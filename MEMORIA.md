# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/m3-corre- **Data da Última Atualização:** 2026-07-31T12:41:00Z
- **Responsável:** IA Assistente (Arquiteto Principal GovSec Shield)
- **Status Atual:** Estabilização estrita M3.2 100% CONCLUÍDA e HOMOLOGADA. Fluxo real Redpanda/Kafka e resiliência do worker totalmente comprovados.

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

### 3. Homologação Estrita da Sprint M3.2 (2026-07-31)
- [x] **Healthcheck por Readiness File (`/tmp/correlation-worker.ready`):** Criado estritamente após a conexão bem-sucedida ao Redpanda/Kafka (`consumer.start()`) e removido em paradas/falhas.
- [x] **Init Container `db-migrations`:** Serviço dedicado no Docker Compose executando `alembic upgrade head` com conclusão bem-sucedida obrigatória antes da inicialização do `correlation-worker`.
- [x] **Política de Resiliência (`restart: unless-stopped`):** Configurada para auto-recuperação do worker em falhas transitórias.
- [x] **Mypy Escopado & Segurança Bandit:** Removidos todos os `type: ignore` inline e configurado `[[tool.mypy.overrides]]` para `aiokafka.*` no `pyproject.toml`. Bandit com 0 vulnerabilidades (sem `#nosec`).
- [x] **Teste `@pytest.mark.kafka_integration`:** Teste de integração real contra Redpanda e PostgreSQL comprovando a cadeia completa (outbox → Redpanda → consumidor → incidente → commit de offset sem toque na outbox pelo consumidor).

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
| **2026-07-31** | Mypy Overrides Escopado para `aiokafka.*` | Eliminação total de `type: ignore` inline no código de produção do projeto, centralizando regras de stubs de terceiros em `pyproject.toml`. |

---

## 📌 Registros Recentes & Próximos Passos
- **Sprint M3.2 Estabilizada & Homologada:** Todos os critérios de aceite cumpridos, 201 testes aprovados, Ruff 0 erros, Mypy 0 erros, Bandit 0 avisos, containers Docker `healthy`.
- **Próximos Passos (Início da Sprint M3.3):**
  1. Implementar rotas REST FastAPI do Incident Management.
  2. Desenvolver a desduplicação e recepção de webhooks do Alertmanager.
  3. Criar a interface do Incident Center e Event Inbox no frontend Next.js.


