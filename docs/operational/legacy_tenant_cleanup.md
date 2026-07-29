# Procedimento Operacional Padrão (SOP) — Saneamento de Dados Legados de Tenant (`alert_acknowledgements.tenant_id`)

**Código:** SOP-GOVSEC-DB-004
**Versão:** 1.1.0
**Classificação:** Uso Interno / Engenharia & Operações (SRE)
**Data de Emissão:** 2026-07-29

---

## 1. Objetivo
Este documento instrui a equipe de Operações/SRE no saneamento e mapeamento de registros históricos da tabela `alert_acknowledgements` que possuem valores de `tenant_id` no formato de slug textual legado (ex: `"betim"`, `"pref-contagem"`), antes da execução da migração de banco de dados `0004_alert_ack_tenant_id_uuid`.

---

## 2. Princípios de Segurança e Integridade
1. **Zero Trust & Dados Canônicos:** Não é permitida a conversão automática de slugs em UUID v5 determinístico, nem o uso de UUIDs padrão de dev/test (`00000000-0000-0000-0000-000000000001`) para substituir tenants reais em staging ou produção.
2. **Fail-Closed:** A migração `0004` opera em modo Fail-Closed. Se a migração encontrar qualquer registro com `tenant_id` não-UUID que não esteja cadastrado no dicionário `LEGACY_TENANT_MAP` da própria migração, o processo será **imediatamente abortado**.
3. **Auditabilidade:** Todo mapeamento deve vincular o slug legado exclusivamente ao UUID oficial cadastrado na tabela de tenants.

---

## 3. Identificação de Registros Legados Não-Conformes

Conecte ao banco de dados PostgreSQL do GovSec Shield e execute a consulta SQL abaixo para identificar todos os slugs de `tenant_id` legados que precisam de saneamento:

```sql
SELECT DISTINCT tenant_id, COUNT(*) AS total_registros
FROM alert_acknowledgements
WHERE tenant_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
GROUP BY tenant_id;
```

---

## 4. Mapeamento e Saneamento de Dados

### 4.1 Obter o UUID Oficial do Tenant Real
Para cada slug retornado na consulta acima (ex: `"betim"` ou `"pref-contagem"`), obtenha o UUID oficial cadastrado na tabela `tenants`:

```sql
SELECT id, name, slug FROM tenants WHERE slug = 'betim';
```

### 4.2 Opção A — Atualização via Banco de Dados (Recomendado)
Atualize os registros históricos na tabela `alert_acknowledgements` com o UUID oficial obtido:

```sql
UPDATE alert_acknowledgements
SET tenant_id = '<UUID_OFICIAL_OBTIDO>'
WHERE tenant_id = 'betim';
```

### 4.3 Opção B — Mapeamento Explícito na Migração Alembic
Caso prefira registrar a conversão na própria migração, edite o arquivo `src/core/infrastructure/db/migrations/versions/0004_alert_ack_tenant_id_uuid.py` e adicione a correspondência no dicionário `LEGACY_TENANT_MAP`:

```python
LEGACY_TENANT_MAP: dict[str, str] = {
    "betim": "<UUID_OFICIAL_DO_TENANT_BETIM>",
}
```

---

## 5. Validação Pré-Migração

Execute novamente a consulta de verificação:

```sql
SELECT DISTINCT tenant_id
FROM alert_acknowledgements
WHERE tenant_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
```

O resultado deve ser **0 linhas retornadas** antes de rodar `alembic upgrade head`.

---

## 6. Execução e Downgrade da Migração

### Executar Migração
```bash
poetry run alembic upgrade head
```

### Reverter Migração (Downgrade)
```bash
poetry run alembic downgrade -1
```

A coluna `tenant_id` retornará ao tipo `VARCHAR(64)` preservando os dados intactos.
