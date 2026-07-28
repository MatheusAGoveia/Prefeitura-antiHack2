# ADR-002: Seleção do Banco de Dados Operacional (OLTP)

- **Status:** Aprovado
- **Data:** 27 de Julho de 2026
- **Contexto:** GovSec Shield (Security OS) - Módulo Core e Security Kernel

## 1. Contexto e Problema
Com a adoção do ecossistema Kafka/Redpanda (ADR-001) e suas garantias de entrega *at-least-once*, a plataforma requer um mecanismo robusto no lado do consumidor para garantir idempotência e consistência transacional ACID.

## 2. Decisão
Decidimos utilizar o **PostgreSQL** como o Banco de Dados Operacional padrão para os Bounded Contexts estruturais (Core Platform, Security Kernel, Knowledge Base).

## 3. Regras de Implementação
1. **Tabela de Deduplicação / Inbox (`PROCESSED_EVENTS`):** Contendo `correlation_key` + `tenant_id` com restrição UNIQUE.
2. **Lock Otimista:** Atualizações de status na entidade `INCIDENT` usarão a coluna `version` (INT) para evitar *Lost Updates* em acessos concorrentes por IA e Analistas SOC.
3. **Colunas JSONB:** Armazenamento de esquemas canônicos e metadados flexíveis da IA.
4. **Isolamento de Tenants:** Multi-tenancy via **Row Level Security (RLS)** com execução de `SET LOCAL app.tenant_id = '...'` em cada transação via PgBouncer.
