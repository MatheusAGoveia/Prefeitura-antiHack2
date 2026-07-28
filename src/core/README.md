# Módulo Core (Core Platform)

O **Core Platform** é o módulo orquestrador e fundacional do **GovSec Shield (Security OS)**.

---

## 🏗️ Responsabilidades

1. **Orquestração de Commands e Eventos:** Roteamento via `CommandBus` e publicação via `EventBus` (Redpanda/Kafka).
2. **Policy Engine (OPA Integration):** Validação de políticas de segurança ANTES de qualquer mutação de estado (INV-005).
3. **Security Kernel:** Autenticação via JWT Bearer Tokens e autorização RBAC (Roles: `viewer`, `analyst`, `engineer`, `security_admin`, `system_admin`).
4. **Gerenciamento de Tenants:** Entidade `Tenant`, persistência relacional com PostgreSQL e migrações versionadas com Alembic.

---

## 🛠️ Comandos Principais

```bash
# Rodar servidor de API FastAPI
make core-run

# Executar testes unitários e de integração do Core
make core-test

# Executar migrações de banco de dados do Core
make core-migrate
```

---

## 🌐 Endpoints HTTP

- `POST /api/v1/tenants` (Requer `SYSTEM_ADMIN`) — Cria um novo Tenant.
- `GET /api/v1/tenants` (Requer `VIEWER`) — Lista os Tenants cadastrados.
- `POST /api/v1/logs` (Requer `ANALYST`) — Ingere logs no barramento de eventos.
