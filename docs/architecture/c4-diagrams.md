# Diagramas de Arquitetura C4 — GovSec Shield

Este documento especifica a arquitetura do **GovSec Shield** através do modelo C4 (Contexto, Contêineres e Componentes) utilizando sintaxe **Mermaid**.

---

## 1. Nível C1 — Diagrama de Contexto (System Context)

O Diagrama de Contexto ilustra o GovSec Shield no centro do ecossistema de segurança governamental, detalhando as interações com analistas de SOC, administradores municipais e sistemas externos integrados.

```mermaid
graph TD
    user_soc["👤 Analista SOC Municipal<br/>[Operador de Segurança]"]
    user_admin["👤 Administrador do Sistema<br/>[SysAdmin / SecAdmin]"]
    wazuh_collector["🖥️ Agentes de Telemetria<br/>[Wazuh / Zabbix / Firewalls]"]
    opa_engine["⚙️ OPA Policy Engine<br/>[Open Policy Agent - INV-005]"]
    external_misp["🌐 Threat Feeds Externos<br/>[MISP / AlienVault OTX]"]

    subgraph GovSecSystem ["🛡️ GovSec Shield — Security OS"]
        core_system["Plataforma Operacional de Segurança Governamental"]
    end

    user_soc -->|"Monitora alertas e mitiga incidentes (HTTPS)"| core_system
    user_admin -->|"Gerencia tenants, políticas e usuários (HTTPS)"| core_system
    wazuh_collector -->|"Envia logs e telemetria brutos (Syslog/REST/gRPC)"| core_system
    core_system -->|"Valida políticas e autorizações de comando (HTTP)"| opa_engine
    core_system -->|"Enriquece indicadores de ameaças IoC (REST)"| external_misp
```

---

## 2. Nível C2 — Diagrama de Contêineres (Containers Diagram)

O Diagrama de Contêineres descreve a topologia interna das aplicações, barramentos de mensageria e bancos de dados que compõem o GovSec Shield.

```mermaid
graph TD
    subgraph FrontendLayer ["Layer 1: Frontend & Dashboard"]
        dashboard_web["🖥️ SOC Dashboard<br/>[Next.js 14 / React 18 / Tailwind CSS]<br/>Interface web interativa para operadores de SOC"]
    end

    subgraph ApiGatewayLayer ["Layer 2: API & Gateway"]
        fastapi_app["⚡ Core Platform API<br/>[Python 3.12 / FastAPI / Uvicorn]<br/>API RESTful assíncrona e endpoints de ingestão"]
    end

    subgraph SecurityKernelLayer ["Layer 3: Security & Policies"]
        opa_container["🔒 OPA Engine<br/>[Open Policy Agent Container]<br/>Validador de políticas Rego (INV-005)"]
    end

    subgraph BrokerLayer ["Layer 4: Message Broker"]
        redpanda_broker["🚀 Redpanda Broker<br/>[C++ Kafka API Compatible]<br/>Barramento de eventos append-only de alta velocidade"]
    end

    subgraph StorageLayer ["Layer 5: Persistence & Cache"]
        postgres_db[("🐘 PostgreSQL 16 DB<br/>[PostgreSQL + RLS Enabled]<br/>Banco OLTP transacional multi-tenant com RLS")]
        redis_cache[("⚡ Redis 7 Cache<br/>[In-Memory Cache]<br/>Cache de sessões JWT e taxa de limite (Rate Limit)")]
    end

    dashboard_web -->|"Consome API via REST / JSON (HTTPS)"| fastapi_app
    fastapi_app -->|"Valida escopo e autorização (HTTP)"| opa_container
    fastapi_app -->|"Publica e consome eventos de domínio (Kafka Protocol)"| redpanda_broker
    fastapi_app -->|"Persiste entidades com RLS e Lock Otimista (AsyncPG)"| postgres_db
    fastapi_app -->|"Armazena sessões e limites (RESP)"| redis_cache
```

---

## 3. Nível C3 — Diagrama de Componentes (Component Diagram: Core Platform)

O Diagrama de Componentes detalha os módulos internos do **Core Platform** (`src/core/`), demonstrando o fluxo interno CQRS, Security Kernel e acesso a dados.

```mermaid
graph TD
    subgraph CorePlatformAPI ["src/core/interfaces/rest/"]
        rest_routers["API Routers<br/>[routers.py]<br/>Endpoints REST FastAPI"]
        rest_deps["Dependency Container<br/>[dependencies.py]<br/>Injeção de dependências FastAPI"]
    end

    subgraph SecurityKernelModule ["src/core/infrastructure/security/"]
        sec_kernel["SecurityKernel<br/>[kernel.py]<br/>Autenticação JWT e RBAC Guard"]
        jwt_utils["JWTUtils<br/>[jwt.py]<br/>Validador de assinaturas HMAC/RSA"]
    end

    subgraph CQRSApplicationModule ["src/core/application/"]
        command_bus["CommandBus<br/>[command_bus.py]<br/>Despachante de comandos CQRS com OPA Gate"]
        event_bus["EventBus<br/>[event_bus.py]<br/>Publicador de eventos de domínio"]
        tenant_handlers["Command Handlers<br/>[handlers.py]<br/>CreateTenantHandler / IngestLogHandler"]
        query_handlers["TenantQueryHandler<br/>[queries.py]<br/>Processador de consultas de leitura"]
    end

    subgraph InfrastructureDBModule ["src/core/infrastructure/db/"]
        uow["UnitOfWork<br/>[unit_of_work.py]<br/>Gerenciador de transações assíncronas"]
        tenant_repo["PostgresTenantRepository<br/>[repositories.py]<br/>Repositório de tenants no PostgreSQL com RLS"]
        opa_client["OPAClient<br/>[opa_client.py]<br/>Cliente HTTP para validação de políticas OPA"]
    end

    rest_routers -->|"Autentica requisição"| sec_kernel
    sec_kernel -->|"Valida Token Bearer"| jwt_utils
    rest_routers -->|"Envia Command"| command_bus
    rest_routers -->|"Executa Query"| query_handlers
    
    command_bus -->|"Consulta permissão OPA"| opa_client
    command_bus -->|"Despacha Command validado"| tenant_handlers
    
    tenant_handlers -->|"Persiste estado via UoW"| uow
    uow -->|"Opera sobre o repositório"| tenant_repo
    tenant_handlers -->|"Publica evento de domínio"| event_bus
    query_handlers -->|"Lê direto do repositório"| tenant_repo
```
