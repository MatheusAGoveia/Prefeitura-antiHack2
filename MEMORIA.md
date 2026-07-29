# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/core-platform`
- **Data da Última Atualização:** 2026-07-29T18:38:00Z
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

### 4. Correção da Migração Segura 0004 e Saneamento de Dados Legados (2026-07-29)
- [x] **Migração Alembic (`0004_alert_ack_tenant_id_uuid.py`):**
  - Removido o mapeamento automático do slug `"betim"` para o UUID de dev/test (`00000000-0000-0000-0000-000000000001`).
  - `LEGACY_TENANT_MAP` mantido como dicionário explícito configurável por ambiente.
  - Caso existam slugs não mapeados para o UUID oficial do tenant real, a migração falha fechada (`Fail-Closed`) com mensagem explicativa e instrução de remediação.
  - Proibida a geração de UUID v5 ou aleatório.
  - `upgrade()` e `downgrade()` simétricos e reversíveis.
- [x] **Documentação Operacional (SOP-GOVSEC-DB-004):**
  - Atualizado [`docs/operational/legacy_tenant_cleanup.md`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/operational/legacy_tenant_cleanup.md) removendo a instrução de associar `"betim"` ao UUID de dev/test.
  - Orientado o saneamento manual via busca do UUID oficial do tenant na tabela `tenants` ou registro explícito em `LEGACY_TENANT_MAP`.
  - Formatado sem espaços em branco no final de linhas.

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
| **2026-07-29** | Migração Fail-Closed sem Defaults Sintéticos | Slugs legados não são mapeados automaticamente para UUID de dev; exigem cadastro do UUID oficial real ou falham a migração. |
