# GovSec Shield (Security OS) — Prefeitura-antiHack2
GovSec Shield é uma plataforma de segurança cibernética para ambientes governamentais baseada no paradigma de Security Operating System (Security OS), responsável por centralizar observabilidade, descoberta de ativos, correlação de eventos, inteligência de ameaças, auditoria, governança de segurança e orquestração de respostas a incidentes por meio de uma arquitetura modular orientada a eventos.

---

## 📐 Visão Geral da Arquitetura

O **GovSec Shield** não é um SIEM acoplado a uma IA, mas um **Sistema Operacional de Segurança** modular e desacoplado. As ferramentas externas (como Zabbix, Wazuh, Caldera) atuam como drivers/conectores (Adapters via ACL - Anti-Corruption Layer). O núcleo centraliza o domínio, as regras de negócio, a autorização e a governança.

### Princípios Fundamentais
1. **Domain First:** O domínio governa a plataforma. Bancos, frameworks e modelos de IA são substituíveis; o domínio, não.
2. **Event First:** Toda alteração de estado relevante gera um evento auditável (Append-Only).
3. **Security by Default & Zero Trust:** Negação de acesso por padrão. Comunicação interna exige verificação do Security Kernel.
4. **AI is Advisory:** A Inteligência Artificial atua de forma consultiva/recomendativa. Ela nunca altera estado de banco diretamente nem executa mutações sem passar pelo Policy Engine (e aprovação humana nos níveis iniciais).
5. **Separacao CQRS:** Separação entre intenções de mutação (Commands) e consultas (Queries).

---

## 🛠️ Stack Tecnológica Base

- **Linguagem / Runtime:** Python 3.10+ (concorrência com `asyncio`)
- **Validação de Dados:** Pydantic v2
- **Framework Web / API:** FastAPI
- **Banco de Dados Operacional (OLTP):** PostgreSQL (com RLS / Multi-Tenancy e Lock Otimista)
- **Data Lake / Analytics:** ClickHouse / OpenSearch
- **Message Broker:** Redpanda / Apache Kafka (Partition Key por `AssetID`)
- **Segurança & Políticas:** OPA (Open Policy Agent) / Cedar / HashiCorp Vault
- **Observabilidade:** OpenTelemetry (Traces, Metrics, Logs via OTel Collector + Grafana/Prometheus/Tempo)

---

## 📁 Estrutura de Diretórios (Monorepo)

```text
GovSec-Shield/
├── README.md
├── requirements.txt / pyproject.toml
├── docs/                             # Documentação Técnica e Arquitetural (ADRs, M0.1-M2.0)
│   ├── adr/                          # Architecture Decision Records (ADR-001, ADR-002, etc.)
│   ├── architecture/                 # Modelos ER, Diagramas C4, Event Storming
│   ├── runbooks/                     # Procedimentos operacionais SRE
│   └── playbooks/                    # Playbooks de resposta a incidentes
├── src/
│   ├── core/                         # Core Platform (Orquestrador & Estado)
│   ├── security/                     # Security Kernel (IAM, RBAC, Policy Engine OPA)
│   ├── asset/                        # Asset Discovery & Port Scanning (Reconhecimento)
│   ├── incident/                     # Gestão de Incidentes & Timeline Imutável
│   ├── risk/                         # Risk Engine (Cálculo determinístico CVSS/EPSS)
│   ├── intelligence/                 # Threat Intelligence (STIX/TAXII, IoCs)
│   ├── response/                     # Response Engine & Playbook Executor
│   ├── ai_gateway/                   # AI Services & Agent Orchestrator (LLM Routing)
│   ├── monitoring/                   # Observabilidade e Métricas
│   ├── connectors/                   # Camada ACL (Adapters para Wazuh, Zabbix, etc.)
│   ├── shared/                       # Kernel compartilhado, DTOs, Event/Command Bus Base
│   └── api/                          # FastAPI Gateway (REST / WebSockets)
└── tests/                            # Testes Unitários, de Integração e Contratos (Pact)
```

---

## 🚀 Módulo Inicial: Reconhecimento e Auditoria (GovSec Scanner)

Conforme a especificação inicial, o módulo de **Asset Discovery & Port Scanning** (`src/asset/`) é responsável por:
- Varredura de rede TCP/UDP de alta performance (`asyncio`).
- Coleta de banners e fingerprinting de serviços.
- Validação rigorosa de escopo (**Scope Safety / Whitelist de Sub-redes CIDR** via Pydantic).

---

## 📚 Documentação

Toda a arquitetura e governança do projeto estão detalhadas na pasta [`docs/`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs):

| Documento | Descrição |
| :--- | :--- |
| [`M0.1 — Visão e Bounded Contexts`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/M0.1_Vision_and_Bounded_Contexts.md) | Paradigma Security OS e Bounded Contexts da plataforma. |
| [`M0.3 — Event Storming & Core Flows`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/M0.3_Event_Storming_and_Flows.md) | Fluxo de detecção, triagem, resposta assíncrona/síncrona e audit log. |
| [`M0.4 — Modelo ER do Banco Operacional`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/M0.4_ER_Database_Model.md) | Schema PostgreSQL v5.4, RLS, Compound FKs e Lock Otimista. |
| [`M0.5 & M0.6 — Versionamento & Eventos`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/M0.5_M0.6_Event_Contracts.md) | Envelopamento de eventos, SemVer e Schema Registry. |
| [`M0.7 — Modelo Canônico de Commands`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/M0.7_Canonical_Commands_Model.md) | Especificação de Commands, CQRS, idempotência e idempotency keys. |
| [`M0.8 — Modelo Operacional & Capacidades`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/M0.8_Operational_Capability_Model.md) | Níveis de Maturidade (M0 a M9), KPIs, DoR e DoD. |
| [`M0.9 & M1.0 — Playbook & Padrões`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/M0.9_Engineering_Playbook.md) | Padrões de código, estratégia Git Flow, DevSecOps e CI/CD. |
| [`ADRs (001 a 003)`](file:///c:/Users/matheus.damiao/Desktop/AntiHackin/Prefeitura-antiHack2/docs/adr) | Decisões Arquiteturais (Redpanda/Kafka, PostgreSQL, Storage). |

---

## 📈 Modelo de Maturidade (Capability Maturity Model)

- **M0 - Arquitetura (Foundation):** Estrutura de domínio, ADRs, Bounded Contexts 
- **M1 - Observabilidade:** Coleta de logs, métricas e tracing (OTel) 
- **M2 - Monitoramento:** Detecção de anomalias e falhas
- **M3 - Correlação:** União de eventos em incidentes (CEP) *(Nível Atual)*
- **M4 - Threat Intelligence:** Enriquecimento com IoCs, STIX/TAXII, MITRE ATT&CK
- **M5 - AI Advisory (Read-Only):** Sugestões de mitigação via LLMs/RAG
- **M6 - AI Copilot:** Assistente em linguagem natural para operacionar o SOC
- **M7 - Automação:** Execução automática de playbooks determinísticos
- **M8 - Red Team Autônomo:** Simulação contínua de ataques (Atomic / Caldera)
- **M9 - Autonomia Supervisionada:** Resposta ativa supervisionada por política
