# 🛡️ GovSec Shield — SOC Dashboard MVP

Interface Web desenvolvida em **Next.js 14 (App Router)**, **React 18**, **TypeScript** e **Tailwind CSS** para a Operação de Segurança (SOC) do GovSec Shield.

---

## 🚀 Como Executar

### 1. Pré-requisitos
- **Node.js**: v18.17+ ou v20+
- **API Core Platform**: Rodando em `http://localhost:8000` (`poetry run uvicorn src.api.main:app --reload`)

### 2. Instalação das Dependências
Na pasta `dashboard/`:
```bash
npm install
```

### 3. Execução em Modo de Desenvolvimento
```bash
npm run dev
```

Acesse [http://localhost:3000](http://localhost:3000) no seu navegador.

---

## ⚡ Funcionalidades Implementadas

1. **Autenticação Simulada (JWT)**:
   - Obtenção do token JWT assinado diretamente do endpoint `/api/v1/auth/token` do Core Platform.
   - Armazenamento automático no `localStorage` (`govsec_token`) e envio no cabeçalho `Authorization: Bearer <token>`.

2. **Visão Geral (Dashboard / SOC)**:
   - Indicador de status em tempo real do backend FastAPI (`/healthz` e `/ready`).
   - Cards de métricas operacionais (Total de Tenants, PostgreSQL RLS, Zero Trust / OPA).
   - Progresso do projeto via parser dinâmico do `MEMORIA.md`.

3. **Gerenciamento de Tenants (`/tenants`)**:
   - Listagem completa dos Tenants registrados na base de dados PostgreSQL.
   - Formulário Modal para cadastro de novas entidades/secretarias municipais com auto-geração de `slug`.
   - Filtro de busca por Nome, Slug ou UUID.

4. **Central de Logs & Ingestão (`/logs`)**:
   - Tabela de auditoria de eventos registrados.
   - Modal simulador de ingestão enviando `IngestLogCommand` para o EventBus (Redpanda Kafka).
   - Inspeção detalhada de payloads JSON em modal.

5. **ScopeSafety Protection Check (`/scope`)**:
   - Validador em tempo real de endereços IP contra sub-redes autorizadas da prefeitura (ex: `10.0.0.0/8`).
