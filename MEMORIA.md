# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/core-platform`
- **Data da Última Atualização:** 2026-07-28T16:34:00Z
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
  - `ADR-001`: Escolha do Message Broker Redpanda/Kafka (`Partition Key = AssetID`).
  - `ADR-002`: Escolha do Banco de Dados Operacional PostgreSQL (RLS, Lock Otimista, Table Inbox `PROCESSED_EVENTS`).
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

### 4. Validação e Testes (2026-07-28)
- [x] Testes unitários (`tests/unit/test_core.py`): 100% de sucesso.
- [x] Testes de integração (`tests/integration/test_db_integration.py`): 100% de sucesso.
- [x] Push realizado na branch `feature/core-platform`.

---

## 🏗️ Decisões Arquiteturais Tomadas
1. **Domain First:** Nenhuma regra de negócio vazada para a infraestrutura ou API.
2. **Zero Trust & Security Kernel:** Negação de acesso por padrão; autorização RBAC verificada no Security Kernel.
3. **OPA Policy Gate (INV-005):** O `CommandBus` consulta obrigatoriamente o `OPAClient` antes de despachar qualquer comando para seu Handler.
4. **Resiliência do EventBus:** Implementado com `aiokafka` para produção e fallback transparente In-Memory para ambiente local/testes.
5. **Deduplicação e Idempotência:** `CorrelationKey` e tabela `PROCESSED_EVENTS` no PostgreSQL com restrição UNIQUE.

---

## 📋 Próximos Passos (Pendentes)
- [ ] Abrir Pull Request da branch `feature/core-platform` para `main` e realizar merge.
- [ ] Implementar o módulo de **Asset Discovery & Port Scanning** (`src/asset/`) utilizando o `BaseScanner` e `ScopeSafety` criados.
- [ ] Criar adaptadores da camada **Connectors (ACL)** para ingestão de alertas de terceiros (Wazuh, Zabbix).
- [ ] Implementar o **Risk Engine** (`src/risk/`) com cálculo determinístico de scores CVSS/EPSS via gRPC.
- [ ] Implementar instrumentação de observabilidade OpenTelemetry (`src/shared/observability/`).

---

## 🧪 Resultados dos Testes
- **Data de Execução:** 2026-07-28
- **Comando:** `python -m pytest tests/unit/test_core.py tests/integration/test_db_integration.py`
- **Resultado:** 6 passed em 1.21s (Cobertura de 66% total na raiz).

---

## 📁 Lista de Arquivos Criados/Modificados
- `README.md`
- `MEMORIA.md`
- `.gitignore`
- `.pre-commit-config.yaml`
- `Makefile`
- `pyproject.toml`
- `requirements.txt`
- `alembic.ini`
- `docker/compose/docker-compose.yml`
- `configs/dev/.env.example`
- `scripts/local-dev/start.sh`
- `docs/M0.1_Vision_and_Bounded_Contexts.md`
- `docs/M0.3_Event_Storming_and_Flows.md`
- `docs/M0.4_ER_Database_Model.md`
- `docs/M0.7_Canonical_Commands_Model.md`
- `docs/M0.8_Operational_Capability_Model.md`
- `docs/adr/ADR-001_Message_Broker_Selection.md`
- `docs/adr/ADR-002_Operational_Database_Selection.md`
- `src/core/domain/entities.py`
- `src/core/domain/repositories.py`
- `src/core/domain/events.py`
- `src/core/application/dto.py`
- `src/core/application/commands.py`
- `src/core/application/interfaces.py`
- `src/core/application/handlers.py`
- `src/core/application/queries.py`
- `src/core/infrastructure/config.py`
- `src/core/infrastructure/db/models.py`
- `src/core/infrastructure/db/repositories.py`
- `src/core/infrastructure/db/unit_of_work.py`
- `src/core/infrastructure/policies/opa_client.py`
- `src/core/infrastructure/messaging/event_bus.py`
- `src/core/infrastructure/messaging/command_bus.py`
- `src/core/infrastructure/security/jwt.py`
- `src/core/infrastructure/security/rbac.py`
- `src/core/infrastructure/security/kernel.py`
- `src/core/infrastructure/db/migrations/env.py`
- `src/core/infrastructure/db/migrations/versions/0001_initial_tenants.py`
- `src/core/interfaces/rest/dependencies.py`
- `src/core/interfaces/rest/routers.py`
- `src/api/main.py`
- `src/api/dashboard_api.py`
- `src/api/static/dashboard.html`
- `src/cli/main.py`
- `src/core/README.md`
- `src/core/security.py`
- `src/asset/scanners/base_scanner.py`
- `tests/unit/test_core.py`
- `tests/unit/test_dashboard_api.py`
- `tests/integration/test_db_integration.py`
