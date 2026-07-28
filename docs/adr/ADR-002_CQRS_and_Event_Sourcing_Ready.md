# ADR 002: Adoção de CQRS e Event Sourcing Ready

## Status
Aceito

## Contexto
O **GovSec Shield** opera como um Sistema Operacional de Segurança Governamental sob alta volatilidade de dados e requisitos de auditoria militar/governamental. 

As operações da plataforma possuem naturezas fundamentalmente distintas:
1. **Escritas (Commands / Intenções de Mudança de Estado):** Exigem validações rigorosas de segurança pelo Security Kernel, aplicação de regras no OPA (Open Policy Agent - INV-005), verificação de escopo (ScopeSafety), controle de concorrência e autorização por papéis (RBAC).
2. **Leituras (Queries / Consultas Operacionais do SOC):** Exigem altíssimo desempenho, agregação em tempo real, visualização em dashboards e paginação flexível sem bloquear a execução de pipelines de resposta automatizada.
3. **Auditoria Legal e Replay:** Necessidade de registrar a rastreabilidade histórica completa de *quem*, *quando* e *por quê* uma ação de mitigação ou comando foi executado.

Modelos CRUD tradicionais onde a mesma entidade é lida e gravada diretamente no banco de dados violam a separação de responsabilidades (SRP), criam gargalos de concorrência e dificultam a reconstrução do histórico de segurança.

## Decisão
Decidimos adotar o padrão **CQRS (Command Query Responsibility Segregation)** na camada de aplicação do Módulo Core Platform e estruturar os contratos de domínio sob a arquitetura **Event Sourcing Ready**.

### Princípios de Design Adotados:
1. **Separação Rígida entre Commands e Queries:**
   - **Commands (`src/core/application/commands.py`):** Encapsulam a intenção de modificar o estado do sistema (ex: `CreateTenantCommand`, `IngestLogCommand`, `UpdateTenantCommand`, `DeleteTenantCommand`). Retornam confirmação ou DTO de alteração. São processados assincronamente pelo `CommandBus`.
   - **Queries (`src/core/application/queries.py`):** Encapsulam intenções de leitura de dados (ex: `ListTenantsQuery`, `ListLogsQuery`). São puras, síncronas/assíncronas de leitura e **nunca modificam o estado do sistema**.
2. **Politica OPA Gate obrigatória no CommandBus (INV-005):** Nenhum Command é entregue ao seu Handler sem antes ser auditado e autorizado pela engine OPA.
3. **Emissão Obrigatória de Eventos Imutáveis de Domínio (M0.6):** Toda mudança de estado aprovada por um Command Handler deve obrigatoriamente publicar um evento de domínio canônico (ex: `TenantCreatedEvent`, `LogIngestedEvent`) no `EventBus`.
4. **Event Sourcing Ready:** A estrutura de eventos possui envelopes auto-contidos com `event_id`, `correlation_id`, `tenant_id`, `timestamp` (UTC ISO 8601) e dados completos do estado, preparando o sistema para reconstrução histórica de agregações via log append-only.

## Consequências

### Impactos Positivos:
- **Desempenho e Escalabilidade Independente:** Leitura e escrita podem ser otimizadas separadamente (ex: leituras direto em views/índices ou réplicas de leitura; escritas com locks otimistas em transações curtas).
- **Rastreabilidade e Auditabilidade Total:** Impossibilidade de alterações de estado "silenciosas". Toda mudança gera um evento imutável auditável.
- **Integração Fluida com IA e Automação:** Agentes de IA consomem eventos de domínio e submetem Commands via `CommandBus`, submetidos às mesmas validações impostas a usuários humanos.
- **Preparação para Event Sourcing Completo:** Capacidade futura de reprocessar eventos do passado recente (*Event Replay*) para reconstruir estados de ativos durante investigações pós-incidente.

### Impactos Negativos:
- **Complexidade de Código Inicial:** Exige a criação de classes distintas para Command, Query, Handler e DTOs, aumentando a verbosidade em comparação a controllers CRUD simples.
- **Eventual Consistency:** Em fluxos assíncronos desacoplados, a visão de leitura pode ter pequenos milissegundos de atraso em relação à confirmação da gravação.

## Alternativas Consideradas

1. **CRUD Tradicional (ActiveRecord / Monolítico):**
   - *Motivo da Rejeição:* Viola a separação de leitura e escrita, cria acoplamento entre regras de segurança e telas de visualização, e dificulta a auditoria transparente de comandos de mitigação.
2. **Event Sourcing Puro Imediato (Sem banco OLTP tradicional):**
   - *Motivo da Rejeição:* Complexidade excessiva na reconstrução de snapshots para a versão M0/M1 e custos desnecessários de projeção imediata, sendo mantida a estratégia *Event Sourcing Ready* com PostgreSQL OLTP como storage primário.
