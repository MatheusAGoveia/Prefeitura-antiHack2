# ADR 003: Implementação de Soft Delete para auditoria

## Status
Aceito

## Contexto
Em ambientes de segurança governamental e gestão pública (GovSec), o descarte ou exclusão física imediata (*Hard Delete*) de registros do banco de dados (ex: Tenants, Ativos de TI, Logs e Históricos de Alertas) acarreta graves problemas operacionais e legais:
1. **Perda de Rastreabilidade Histórica:** Dificuldade em responder a auditorias de órgãos de controle (ex: TCU, CGU, LGPD) ao tentar reconstruir eventos ocorridos sob a gestão de uma secretaria ou ativo removido.
2. **Quebra de Integridade Referencial:** Exclusão em cascata (*CASCADE DELETE*) de logs de segurança, alertas ou regras de mitigação associadas ao ativo ou tenant excluído.
3. **Impossibilidade de Rollback/Recuperação:** Risco de exclusão acidental por operador humano ou falha de script administrativo sem capacidade imediata de restauração.

## Decisão
Decidimos que **nenhuma entidade de domínio relevante no GovSec Shield será fisicamente excluída do banco de dados operacional (Hard Delete)**. Em vez disso, adotamos a estratégia **Soft Delete para Auditoria Governamental**.

### Diretrizes de Implementação:
1. **Alteração de Estado de Domínio:** A exclusão de uma entidade (ex: `DeleteTenantCommand`) é tratada no domínio como uma desativação transicional, alterando o atributo `status` para `INACTIVE` ou `SUSPENDED` (ex: `tenant.deactivate()`).
2. **Timestamp de Atualização:** A ação atualiza o atributo `updated_at` com o timestamp exato UTC (`datetime.now(timezone.utc)`).
3. **Filtros Padrão de Leitura:** As consultas cotidianas do SOC aplicam filtros para exibir por padrão apenas entidades ativas (`status = 'ACTIVE'`), disponibilizando parâmetros explícitos (`status=INACTIVE`) para auditores e peritos.
4. **Preservação de Logs e Eventos:** Todos os logs de auditoria e eventos históricos associados ao tenant ou ativo permanecem intocados na tabela `PROCESSED_EVENTS` e nos tópicos de mensageria.

## Consequências

### Impactos Positivos:
- **Conformidade Legal e Governamental (Zero Data Loss):** Total conformidade com leis de retenção de dados públicos e auditoria de segurança da informação.
- **Restauração Imediata (Rollback):** Possibilidade de reativar um tenant ou ativo com um único comando de atualização (`UpdateTenantCommand(status='ACTIVE')`).
- **Integridade Referencial Preservada:** Chaves estrangeiras e relacionamentos com logs de auditoria históricos permanecem válidos no PostgreSQL.

### Impactos Negativos:
- **Crescimento do Volume de Dados:** Tabelas mantêm registros inativos indefinidamente, exigindo particionamento futuro ou estratégias de expurgo arquivístico em *Cold Storage*.
- **Cuidados na Camada de Leitura:** Necessidade de garantir que queries do painel operacional filtrem adequadamente registros inativos para evitar poluição visual para os analistas do SOC.

## Alternativas Consideradas

1. **Hard Delete (DELETE SQL nativo):**
   - *Motivo da Rejeição:* Totalmente inaceitável em um ambiente Security OS governamental devido ao risco de destruição de provas de auditoria e quebra de integridade.
2. **Tabelas de Arquivo Morto (Archive Tables / Shadow Tables):**
   - *Motivo da Rejeição:* Exige a manutenção do dobro de tabelas no banco PostgreSQL (`tenants_archive`, `assets_archive`), criando complexidade de migração Alembic desnecessária nesta fase.
