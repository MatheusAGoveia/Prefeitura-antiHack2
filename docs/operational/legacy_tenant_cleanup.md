# Procedimento Operacional Padrão (SOP) — Saneamento de Dados Legados de Tenant (`alert_acknowledgements.tenant_id`)

**Código:** SOP-GOVSEC-DB-004  
**Versão:** 1.0.0  
**Classificação:** Uso Interno / Engenharia & Operações (SRE)  
**Data de Emissão:** 2026-07-29  

---

## 1. Objetivo
Este documento instrui a equipe de Operações/SRE no saneamento e mapeamento de registros históricos da tabela `alert_acknowledgements` que possuem valores de `tenant_id` no formato de slug textual legado (ex: `"betim"`), antes da execução da migração de banco de dados `0004_alert_ack_tenant_id_uuid`.

---

## 2. Princípios de Segurança e Integridade
1. **Zero Trust & Dados Canônicos:** Não é permitida a geração de UUIDs v5 determinísticos a partir de slugs, nem a criação de UUIDs aleatórios para mascarar dados.
2. **Fail-Closed:** Se a migração `0004` encontrar qualquer registro com `tenant_id` não-UUID que não esteja presente no mapeamento canônico explícito, o processo de migração será **imediatamente interrompido com falha explícita**.
3. **Auditabilidade:** Todas as alterações devem ser gravadas e associadas ao UUID canônico oficial cadastrado no ecossistema do Tenant.

---

## 3. Identificação de Registros Legados Não-Conformes

Conecte ao banco de dados PostgreSQL do GovSec Shield e execute a query abaixo para identificar valores de `tenant_id` legados que não correspondem a um UUID válido:

```sql
SELECT DISTINCT tenant_id, COUNT(*) AS total_registros
FROM alert_acknowledgements
WHERE tenant_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
GROUP BY tenant_id;
```

---

## 4. Mapeamento e Saneamento

### 4.1 Mapeamentos Canônicos Pré-Aprovados
Os seguintes slugs legados possuem mapeamento oficial pré-aprovado na migração `0004`:

| Slug Legado | UUID Canônico Mapeado | Descrição |
| :--- | :--- | :--- |
| `betim` | `00000000-0000-0000-0000-000000000001` | Tenant Padrão Dev/Test |
| `dev` | `00000000-0000-0000-0000-000000000001` | Tenant Padrão Dev |

### 4.2 Remediar Novos Slugs Desconhecidos (Se Existirem)
Caso a consulta na Seção 3 retorne slugs que não estejam listados acima (ex: `"contagem"`):

1. **Obter o UUID Oficial do Tenant:**
   ```sql
   SELECT id, name, slug FROM tenants WHERE slug = 'contagem';
   ```

2. **Atualizar os Registros Legados:**
   ```sql
   UPDATE alert_acknowledgements
   SET tenant_id = '<UUID_OFICIAL_OBTIDO>'
   WHERE tenant_id = 'contagem';
   ```

3. **Re-executar a Validação:**
   Execute a query da Seção 3. O resultado deve ser **0 linhas retornadas**.

---

## 5. Execução da Migração

Após garantir que todos os dados legados foram saneados ou mapeados:

```bash
poetry run alembic upgrade head
```

---

## 6. Procedimento de Rollback (Downgrade)

Caso seja necessário reverter a migração:

```bash
poetry run alembic downgrade -1
```

O tipo da coluna `tenant_id` será revertido para `VARCHAR(64)` de forma transparente e coerente.
