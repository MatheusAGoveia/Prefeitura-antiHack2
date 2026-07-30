# ADR 005: Correlação Determinística e Central de Incidentes (Capability M3)

## Status
Aceito

## Contexto
O **GovSec Shield** necessita evoluir de um sistema de ingestão e monitoramento de telemetria/alertas (Capability M2) para uma plataforma capaz de estruturar, correlacionar e gerenciar a resposta a incidentes operacionais e de segurança governamentais (Capability M3).

Sem um mecanismo formal e determinístico de correlação:
1. Múltiplas telemetrias e alertas relacionados ao mesmo problema técnico ou vetor de ameaça geram tempestades de alertas (*alert fatigue*) para os operadores humanos do SOC municipal.
2. A falta de deduplicação e agrupamento por tenant e ativo gera incidentes duplicados e desalinhamento de estado.
3. Eventos sem identificação precisa de ativos correm o risco de disparar automações precipitadas ou incidentes críticos inadequados.

Além disso, a arquitetura do GovSec Shield exige estrita aderência aos princípios **Domain First**, **Clean Architecture**, **CQRS**, **Zero Trust**, **Multi-tenancy por UUID** e **Human-in-Control** (sem IA ou respostas autônomas não supervisionadas nesta fase).

## Decisões

### 1. Limite entre M3 e M4
- **Capability M3 (Central de Incidentes & Correlação Determinística):** Responsável por recepcionar `SecurityEvent` normalizados, aplicar regras determinísticas tipadas, agrupar eventos em `Incident` via `CorrelationKey`, persistir o ciclo de vida transacional no PostgreSQL, expor APIs REST/GraphQL para o dashboard Next.js e registrar toda ação humana auditável.
- **Capability M4 (Orquestração & Automação de Segurança):** Responsável por definição estática de contratos para jobs de segurança (`SecurityJob`), adaptadores de ferramentas (`ToolAdapter`), gestão de engajamentos (`Engagement`) e escopo de alvos (`ScopeTarget`). M3 apenas define os contratos preparatórios abstratos para M4, sem qualquer implementação concreta, execução de scanners, ferramentas ofensivas, filas de execução ou rotinas ativas.

### 2. Identidade Canônica de Tenant
- `tenant_id` (UUID v4) é a **única** identidade canônica e obrigatória em todas as entidades, Value Objects, eventos de domínio e comandos de M3.
- Operações sem `tenant_id` válido são terminantemente rejeitadas pelo Security Kernel.

### 3. Tratamento de Ativos Não Resolvidos (`UnresolvedAssetEvent`)
- Quando um `SecurityEvent` é ingerido sem associação direta com um `Asset` cadastrado no domínio do tenant (`asset_id is None`), o sistema **nunca** gera um incidente crítico automático.
- Em vez disso, o evento fica inequivocamente marcado como não resolvido (`is_asset_resolved = False`) e gera o contrato de evento de domínio `UnresolvedAssetEvent` (`event_id`, `tenant_id`, `security_event_id`, `occurred_at_utc`), que será persistido e direcionado para a fila de tratamento manual (*Event Inbox*) na M3.1. Em M3.0, este contrato não realiza publicação em brokers de mensageria nem cria incidentes.

### 4. Chave de Correlação Determinística e Versionada (`CorrelationKey`)
- A correlação de eventos utiliza uma chave determinística, estável, versionada e imutável formada por:
  $$\text{CorrelationKey} = f(\text{tenant\_id}, \text{rule\_id}, \text{rule\_version}, \text{asset\_key}, \text{category}, \text{time\_window})$$
- A inclusão explícita de `rule_version` garante que alterações ou evolução no algoritmo da regra gerem chaves e hashes SHA-256 distintos, prevenindo agrupamento indevido entre versões de regras.
- **Invariante de Unicidade Operacional:** Deve existir no futuro **apenas um único incidente aberto** (`IncidentStatus.OPEN`, `ACKNOWLEDGED`, `INVESTIGATING` ou `CONTAINED`) por tupla `(tenant_id, correlation_key)`. Novos eventos com a mesma chave dentro da janela de correlação são anexados ao incidente existente como `IncidentEvidence`.

### 5. Persistência Transacional Antes da Publicação Assíncrona
- Garantia de **Transactional Outbox / Write-Ahead Persistence**: Todo `SecurityEvent` e transição de estado de `Incident` é gravado no PostgreSQL (fonte transacional de verdade) **antes** de qualquer publicação em tópicos assíncronos do Redpanda/Kafka.

### 6. Regras de Correlação Tipadas e Versionadas
- As regras de correlação de M3 não utilizam interpretadores genéricos de expressões dinâmicas (ex: eval ou string DSLs não tipadas).
- Toda `CorrelationRule` é uma classe/contrato tipado, versionado e testável em Python, herdando da abstração do domínio.

### 7. Imutabilidade e Impossibilidade de Exclusão Física
- Incidentes e evidências **nunca são excluídos fisicamente** (`Zero Data Loss`).
- O encerramento de um incidente é feito via transição para os estados `RESOLVED` ou `CLOSED`.
- Alterações são registradas em logs de auditoria imutáveis com `actor_id`, `timestamp_utc` e `reason`.

### 8. Máquina de Estados do Incidente
O ciclo de vida do incidente obedece estritamente às transições permitidas:
$$\text{OPEN} \longrightarrow \text{ACKNOWLEDGED} \longrightarrow \text{INVESTIGATING} \longrightarrow \text{CONTAINED} \longrightarrow \text{RESOLVED} \longrightarrow \text{CLOSED}$$

## Consequências

### Positivas
- **Prevenção de Alert Fatigue:** Deduplicação determinística garante um único incidente ativo por causa raiz e ativo.
- **Auditabilidade Governamental:** Rastreabilidade completa de todas as alterações com identificação do operador humano responsável.
- **Isolamento Multi-tenant Robusto:** Garantia de que eventos e incidentes pertencem exclusivamente ao `tenant_id` validado.
- **Desacoplamento Limpo:** A camada de domínio permanece 100% isolada de frameworks web, ORMs, brokers de mensageria ou motores de execução.

### Negativas / Limitações
- **Rigidez Inicial de Regras:** Regras tipadas exigem compilação e deploy da aplicação (evitando alteração dinâmica de regras em runtime sem testes prévios).
- **Sem IA ou Automação Autônoma:** Respostas a incidentes dependem obrigatoriamente de intervenção humana declarada (*Human-in-Control*).

## Itens Deliberadamente Adiados para M3.1–M3.5
- Migrações Alembic e tabelas PostgreSQL (`incidents`, `security_events`, `incident_evidences`).
- Endpoints REST FastAPI para listagem, criação e alteração de estado de incidentes.
- Webhook de ingestão de alertas do Alertmanager para a API FastAPI.
- Telas de Incident Center e Event Inbox no dashboard Next.js.
- Regras adicionais de correlação determinísticas.
- Métricas Prometheus para incidentes abertos/resolvidos.
