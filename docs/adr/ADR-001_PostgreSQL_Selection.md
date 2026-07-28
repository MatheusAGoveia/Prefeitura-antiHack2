# ADR 001: Escolha do PostgreSQL como banco de dados principal

## Status
Aceito

## Contexto
O **GovSec Shield** é um Sistema Operacional de Segurança Governamental (Security OS) projetado para gerenciar infraestruturas críticas municipais, órgãos governamentais e secretarias públicas sob ambientes multi-tenant com elevado isolamento de dados. 

A plataforma lida concorrentemente com:
1. **Transações críticas ACID:** Registro de tenants, inventário de ativos, permissões RBAC e estado operacional de incidentes de segurança.
2. **Requisitos de Isolamento Rígoroso (Multi-tenancy):** A necessidade de garantir isolamento de dados entre secretarias (ex: Saúde, Fazenda, Segurança Pública) de forma transparente e à prova de vazamentos acidentais na camada de aplicação.
3. **Persistência de Dados Flexíveis:** Armazenamento de telemetrias semi-estruturadas, relatórios de scanners de vulnerabilidades e envelopes de comandos JSON.
4. **Resiliência Transacional Concorrente:** Necessidade de prevenir escritas concorrentes conflitantes (*Lost Updates*) em incidentes sendo modificados simultaneamente por analistas humanos do SOC e agentes autônomos de IA.

## Decisão
Decidimos adotar o **PostgreSQL 16+** como o sistema de gerenciamento de banco de dados relacional (RDBMS) OLTP padrão para os Bounded Contexts estruturais do GovSec Shield (`Core Platform`, `Security Kernel`, `Asset Management` e `Incident Response`).

### Padrões de Uso Arquitetural:
1. **Multi-Tenancy via Row Level Security (RLS):** Toda tabela de entidade multi-tenant obriga a coluna `tenant_id` e políticas RLS nativas do PostgreSQL (`CREATE POLICY tenant_isolation_policy ON table FOR ALL USING (tenant_id = current_setting('app.current_tenant'))`).
2. **Lock Otimista para Concorrência:** Utilização da coluna `version INT DEFAULT 1` nas entidades mutáveis (ex: `Incident`), validando `WHERE id = :id AND version = :version` para garantir consistência ACID entre operações humanas e de agentes de IA.
3. **Colunas JSONB com Índices GIN:** Armazenamento de esquemas flexíveis de comandos, eventos auditados e resultados de scanners com busca acelerada por índices GIN.
4. **Garantia de Idempotência (Table Inbox):** Tabela `PROCESSED_EVENTS` com restrição `UNIQUE(correlation_key, tenant_id)` para desduplicação imediata na camada de persistência.

## Consequências

### Impactos Positivos:
- **Segurança Nativa no Motor de Banco:** O RLS garante que mesmo se houver falha na aplicação Python (ex: omissão de `WHERE tenant_id = ...`), o motor do PostgreSQL impede a leitura ou escrita cross-tenant.
- **Flexibilidade Híbrida (Relacional + JSON):** Permite estruturar rigorosamente entidades de domínio (Tenants, Users, Assets) enquanto preserva flexibilidade para atributos mutáveis em colunas JSONB.
- **Ecossistema Robusto e Maduro:** Amplo suporte no Python (SQLAlchemy 2.0 async, `asyncpg`), suporte nativo no Docker/Kubernetes e compatibilidade com ferramentas de CDC (Debezium).
- **Consistência ACID Completa:** Garantia de isolamento SERIALIZABLE / READ COMMITTED em operações críticas do Security Kernel.

### Impactos Negativos:
- **Overhead no Pool de Conexões:** Requer gerenciador de conexões como PgBouncer ou pooling otimizado no `asyncpg` para manter o contexto de sessão `app.current_tenant` por requisição.
- **Complexidade de Tuning de Índices GIN:** Tabelas com grande volume de dados JSONB exigem manutenção e otimização periódica de VACUUM e índices.

## Alternativas Consideradas

1. **MongoDB / Document Databases:**
   - *Motivo da Rejeição:* Ausência de Row Level Security (RLS) nativo no motor de dados e suporte transacional complexo ACID multi-documento inferior ao PostgreSQL.
2. **MySQL / MariaDB:**
   - *Motivo da Rejeição:* Suporte ao tipo JSON e índices parciais/GIN inferior ao PostgreSQL; ausência de RLS nativo equivalente e menor flexibilidade para extensões de segurança.
3. **SQLite (Somente Testes Locais/Fallback):**
   - *Motivo da Rejeição:* Rejeitado para produção por ser *single-writer* e não suportar RLS, concorrência assíncrona escalável ou locking otimista avançado.
