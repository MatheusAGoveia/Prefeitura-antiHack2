# 🧠 MEMÓRIA PERSISTENTE — GovSec Shield

> **Propósito:** Este arquivo é o "cérebro" do desenvolvimento do GovSec Shield. Ele registra a evolução do projeto, decisões arquiteturais, tarefas implementadas, pendências e histórico de testes.

---

## 📌 Estado Atual do Projeto
- **Repositório:** `MatheusAGoveia/Prefeitura-antiHack2`
- **Branch Ativa:** `feature/m3.3-incident-center-api`
- **Data da Última Atualização:** 2026-07-31T17:49:00Z
- **Responsável:** IA Assistente (Arquiteto Principal GovSec Shield)
- **Status Atual:** SPRINT M3.3 (Central Operacional de Incidentes e Evidências e Correção dos Bloqueadores) 100% CONCLUÍDA e HOMOLOGADA. Suíte completa expandida para 215 testes unitários e de integração aprovados sem ressalvas (100% PASSED). Validação de qualidade de código nos 9 gates (Ruff, Mypy, Bandit, Compileall, Git Diff, Docker Compose) 100% VERDE. Plataforma pronta para a Sprint M3.4.

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
- [x] **Refinamento de Testes de Regressão:** Teste `test_run_loop_aborts_kafka_offset_commit_when_process_single_message_fails` criado validando com `assert_not_awaited()` que `consumer.commit` não é executado no loop quando o banco falha.
- [x] **Healthcheck por Readiness File (`/tmp/correlation-worker.ready`):** Criado estritamente após a conexão bem-sucedida ao Redpanda/Kafka (`consumer.start()`) e removido em paradas/falhas.
- [x] **Limpeza de Qualidade (Git Diff Check):** Eliminadas linhas em branco excedentes ao final dos arquivos.

### 4. Sprint M3.3 — Central Operacional de Incidentes e Evidências (2026-07-31)
- [x] **Branch Dedicada:** `feature/m3.3-incident-center-api` criada a partir do commit mais recente da M3.2.
- [x] **Identidade do Histórico Real (`history_id`):** `IncidentStatusChange` expandido com `history_id: UUID` repassando o UUID real armazenado no banco com ordenação `ORDER BY timestamp DESC, history_id DESC` e estabilidade determinística.
- [x] **Métricas Pós-Commit e Remoção de `suppress(Exception)`:** Eliminados todos os tratamentos silenciosos de métricas; chamadas a `record_incident_created`, `record_incident_status_transition` e `record_incident_evidence_added` executam rigorosamente após a confirmação transacional no banco.
- [x] **Gauge de Estado Atual (`govsec_open_incidents`):** Gauge Prometheus com label `severity` rastreando a quantidade de incidentes ativos em tempo real, decrementado em transições para `resolved` ou `closed`.
- [x] **Isolamento Real Multi-Tenant Cross-Tenant:** Suíte de testes de integração com `Tenant A` e `Tenant B` reais confirmando `HTTP 404 Not Found` em todos os endpoints (`GET /incidents/{id}`, `GET /incidents/{id}/evidences`, `GET /incidents/{id}/history`, `PATCH /incidents/{id}/status`), e `total=0` em listagens.
- [x] **Validação Estrita de Datas e Timezones (UTC):** Rejeição de datetimes naive com `HTTP 422`, rejeição de `created_from > created_to` com `HTTP 422`, e suporte a limites idênticos (`created_from == created_to`).
- [x] **Contagem de Evidências sem N+1 (`evidence_count`):** Método `get_evidence_counts_batch` em `PostgresIncidentRepository` realizando consulta SQL agregada em lote `COUNT(evidence_id)` indexada por `tenant_id`, fornecendo `evidence_count` precisa nos 3 endpoints HTTP.
- [x] **Mascaramento Completo em Respostas HTTP:** Payloads brutos em respostas HTTP de evidências sanitizam recursivamente senhas, tokens, cookies e chaves de API como `"[REDACTED]"`.
- [x] **Dashboard Grafana (`deploy/grafana/dashboards/golden_signals.json`):** Atualizada a PromQL para `sum(govsec_open_incidents) by (severity)`.
- [x] **Suíte de Testes Ampliada:** 213 testes unitários e de integração passados sem ressalvas (25.09s).

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
| **2026-07-31** | Gauge de Estado em Tempo Real | `govsec_open_incidents` fornece visibilidade SRE instantânea dos incidentes ativos por severidade, decrementando em resoluções pós-commit. |
| **2026-07-31** | Métricas Prometheus Pós-Commit | `CorrelationKafkaConsumer` dispara métricas Prometheus somente APÓS `uow.commit()` no Postgres, garantindo que rollbacks e replays não alterem contadores. |
| **2026-07-31** | Preservação de `history_id` do Domínio | `PostgresIncidentRepository.save` utiliza `history_id=change.history_id` gerado pela entidade de domínio, mantendo a identidade estável no DB e HTTP REST. |
| **2026-07-31** | Reconstrução do Gauge a partir do Postgres | `sync_open_incidents_gauge_from_db` sincroniza o Gauge `govsec_open_incidents` diretamente do banco no startup FastAPI e pós-commit. |
| **2026-07-31** | Mascaramento de Strings com Regex Segura | `sanitize_string_content` mascara tokens `Bearer`, `Basic` e pares `key=val` em strings livres usando regex compiladas de alta performance em uma única passagem. |
| **2026-07-31** | Contrato UTC Zero Estrito (`Z`/`+00:00`) | `GET /api/v1/incidents` rejeita datas naive sem timezone e offsets locais (ex: `-03:00`) com **HTTP 422**, e rejeita `created_from > created_to` com **HTTP 422**. |

---

## 📌 Registros Recentes & Próximos Passos
- **Correção dos Bloqueadores Finais da Sprint M3.3 Finalizada & Homologada (2026-07-31):** Todos os 6 componentes técnicos corrigidos, 215 testes unitários e de integração passados (100% PASSED), Ruff 0 erros, Mypy 0 erros em 123 arquivos, Bandit 0 avisos em 8667 linhas, `compileall` sem erros, `git diff --check` limpo, `docker compose config` válido.
- **Próximos Passos (Pronto para início da Sprint M3.4):**
  1. Apresentar a conclusão detalhada e o resultado dos 9 gates ao usuário.
  2. Iniciar o planejamento da Sprint M3.4 sob demanda do usuário.
