# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/m3-correlation-incidents`
- **Data da Última Atualização:** 2026-07-30T12:46:00Z
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

### 3. Exigência Estrita da Claim Canônica `tenant_id` no JWT (2026-07-29)
- [x] **Segurança & Kernel (`SecurityKernel` & `JWTHandler`):**
  - Removido totalmente qualquer fallback para a claim legada `tenant` (`payload.get("tenant")`).
  - `tenant_id` passa a ser a **única** claim aceita para identidade de tenant no payload JWT.
  - Tokens sem `tenant_id`, com `tenant_id` vazio ou não-UUID são imediatamente rejeitados (retornam `None` ou lançam `PermissionError`).
  - Refresh tokens preservam apenas a claim `tenant_id` com UUID válido.
  - Removida a duplicação da chave `"tenant"` nos novos tokens gerados pela aplicação.
  - Proibida a compatibilidade silenciosa com tokens legados.

### 4. Seleção de Revogação Redis por Ambiente & Fail-Closed (2026-07-29)
- [x] **Seleção Estrita por Ambiente (`src/core/infrastructure/security/jwt.py` & `revocation.py`):**
  - `JWTHandler.get_revocation_store()` delega para a factory `get_token_revocation_store()`.
  - Em `staging` e `production`, o sistema seleciona **obrigatoriamente** `RedisTokenRevocationStore`, independente de `GOVSEC_REDIS_URL` estar preenchida ou vazia. Fallback em memória (`InMemoryTokenRevocationStore`) é **estritamente proibido** fora de `dev`/`test`.
  - Em caso de ausência de URL ou indisponibilidade de conexão com o Redis em staging/produção, a operação falha fechada lançando `RedisRevocationUnavailableError`.
  - Middlewares REST e dependências capturam a exceção e retornam HTTP `503 Service Unavailable` sem vazar credenciais, tokens, URLs ou stack traces.

---

## 🏗️ Decisões Arquiteturais Tomadas (ADRs & Design)

| Data | Decisão | Justificativa |
| :--- | :--- | :--- |
| **2026-07-28** | PostgreSQL como banco principal | Suporte nativo a Row Level Security (RLS) para isolamento multi-tenant estrito por prefeitura. |
| **2026-07-28** | CQRS + Event-Driven | Desacoplamento entre escritas de alto volume (logs de auditoria) e leituras agregadas (dashboards SOC). |
| **2026-07-28** | Policy-as-Code via OPA | Invariante INV-005 exige que todo Command passe pela validação de políticas antes de alterar estado. |
| **2026-07-28** | Soft Delete com timestamp | Regulamentações governamentais proíbem exclusão física de registros de auditoria e configurações. |
| **2026-07-29** | Docker preflight isolado para Alertmanager | Preflight em container dedicado garante PyYAML e amtool sem dependências dinâmicas em runtime. |
| **2026-07-29** | Identidade Estrita de Tenant via `tenant_id` | Eliminação total de fallback da claim legada `tenant`, exigindo `tenant_id` UUID em todas as requisições JWT. |
| **2026-07-29** | Revogação Redis Estrita por Ambiente (Zero In-Memory Fallback em Prod) | Proibição de fallback em memória em staging/produção, forçando `RedisTokenRevocationStore` e propagação de `RedisRevocationUnavailableError` (HTTP 503). |
| **2026-07-29** | Limpeza de Imports de Revogação JWT | Removidos os imports não utilizados `InMemoryTokenRevocationStore` e `RedisTokenRevocationStore` de `src/core/infrastructure/security/jwt.py`, mantendo `BaseTokenRevocationStore` e `get_token_revocation_store`. |
| **2026-07-29** | Validação Integrada M2 Aprovada | Execução estrita do pipeline de 5 passos com 116 testes aprovados, ruff 0 erros, mypy 0 erros, bandit 0 avisos, compileall 0 erros, 8 serviços dev healthy, fire drill OK e preflights de produção OK. |
| **2026-07-29** | Remoção de Ofuscação & Isolação de Estado em Testes | Removidas todas as concatenações artificiais de strings. Adicionada fixture pytest `in_memory_revocation_store` com `try/finally` para isolar e restaurar o estado global de `JWTHandler._revocation_store`. |
| **2026-07-30** | ADR-005: Fundação do M3 | Aprovação da ADR 005 congelando a arquitetura de correlação determinística, isolamento por tenant_id UUID, persistência transacional antes do Kafka e contratos puros de domínio. |
| **2026-07-30** | Validação Estrita de Timestamps UTC | Implementado o helper `_validate_utc_datetime` no domínio M3.0, exigindo estritamente datetimes timezone-aware no fuso UTC (+00:00) em todos os contratos (Asset, SecurityEvent, UnresolvedAssetEvent, Incident, IncidentEvidence, IncidentStatusChange). |

---

## 📌 Registros Recentes & Próximos Passos
- **Sprint M3.0 Concluída & Validada:** Criada a branch `feature/m3-correlation-incidents`, elaborada a ADR 005, definidos os contratos de domínio com validação estrita de `tenant_id` UUID e timestamps UTC. Suíte de testes aprovada com 127/127 testes passando, ruff 0 erros, mypy 0 erros, bandit 0 avisos de média/alta severidade, compileall 0 erros e git diff --check OK.
- **Próximos Passos (Sprint M3.1+):**
  - Implementar migrações Alembic e modelos SQLAlchemy para `incidents`, `security_events`, `incident_evidences` e `assets`.
  - Criar rotas FastAPI REST para gestão de incidentes.
  - Integrar Webhook do Alertmanager.
  - Desenvolver Event Inbox e Incident Center no dashboard Next.js.
