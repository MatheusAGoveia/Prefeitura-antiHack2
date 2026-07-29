# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/core-platform`
- **Data da Última Atualização:** 2026-07-29T18:25:00Z
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

### 3. Refatoração Canônica de Identidade de Tenant (Zero Fallback Slug) (2026-07-29)
- [x] **Segurança & Kernel (`SecurityKernel` & `JWTHandler`):**
  - Removidas conversões implícitas `uuid5(NAMESPACE_DNS, slug)` para `tenant_id`.
  - `_parse_tenant_id` no SecurityKernel valida estritamente `UUID`. Strings inválidas ou ausentes lançam `PermissionError`.
  - `generate_token`, `verify_token` e `refresh_token_async` validam estritamente o tipo `UUID`. Tokens com `tenant_id` ausente, vazio ou não-UUID são rejeitados imediatamente.
  - `dev-token` e `login` em modo dev/test utilizam UUID estável de dev `00000000-0000-0000-0000-000000000001` quando o parâmetro `tenant_id` for omitido.
- [x] **DTOs & Entidades:**
  - `AuditLog`, `AlertAcknowledgement`, `IngestLogDTO`, `AcknowledgeAlertDTO` e `TargetScopeRequest` exigem obrigatoriamente um `UUID` válido para `tenant_id`.
  - Requisições REST com payload contendo `tenant_id` inválido retornam HTTP `400 Bad Request`.
- [x] **Repositórios:**
  - `PostgresAlertAcknowledgementRepository` e `InMemoryAlertAcknowledgementRepository` utilizam validação estrita de UUID no `_parse_uuid`.
  - Paginação no repositório aplica o filtro de tenant por UUID no banco/memória **antes** do `offset` e `limit`.
- [x] **Suíte de Testes & Validação:**
  - Adicionados 8 testes comportamentais obrigatórios cobrindo JWT com UUID válido, rejeição de slug/não-UUID, login dev com UUID estável, OIDC em staging/produção, rejeição de tenant inválido em logs/alerts, isolamento multi-tenant por UUID e paginação com filtro prévio.
  - Suíte total de 112 testes passando (100% de sucesso).
  - Linters `ruff`, `mypy`, `bandit`, `compileall` e `git diff --check` sem erros ou flags de supressão.

---

## 🏗️ Decisões Arquiteturais Tomadas (ADRs & Design)

| Data | Decisão | Justificativa |
| :--- | :--- | :--- |
| **2026-07-28** | PostgreSQL como banco principal | Suporte nativo a Row Level Security (RLS) para isolamento multi-tenant estrito por prefeitura. |
| **2026-07-28** | CQRS + Event-Driven | Desacoplamento entre escritas de alto volume (logs de auditoria) e leituras agregadas (dashboards SOC). |
| **2026-07-28** | Policy-as-Code via OPA | Invariante INV-005 exige que todo Command passe pela validação de políticas antes de alterar estado. |
| **2026-07-28** | Soft Delete com timestamp | Regulamentações governamentais proíbem exclusão física de registros de auditoria e configurações. |
| **2026-07-29** | Docker preflight isolado para Alertmanager | Preflight em container dedicado garante PyYAML e amtool sem dependências dinâmicas em runtime. |
| **2026-07-29** | Identidade Estrita de Tenant via UUID Canônico | Eliminação total de fallback de slug para UUID v5 em autenticação/autorização, assegurando isolamento multi-tenant determinístico. |

---

## 📈 Histórico de Validações e Testes

- **2026-07-29 (Zero Fallback Slug Refactoring):**
  - `poetry run pytest --override-ini="addopts=" -v`: **112 passed** (0 failures).
  - `poetry run ruff check src tests scripts`: **0 issues**.
  - `poetry run mypy src`: **Success (107 source files)**.
  - `poetry run bandit -r src -s B105,B106`: **0 issues**.
  - `poetry run python -m compileall -q src scripts`: **0 errors**.
  - `git diff --check`: **0 errors**.
