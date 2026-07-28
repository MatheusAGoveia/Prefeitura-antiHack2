# ADR-001: Seleção do Message Broker (Event-Driven Backbone)

- **Status:** Aprovado
- **Data:** 27 de Julho de 2026
- **Contexto:** GovSec Shield (Security OS)

## 1. Contexto e Problema
O GovSec Shield opera sob uma Arquitetura Orientada a Eventos (EDA). Ferramentas periféricas (como o Wazuh) podem gerar picos de milhares de alertas por segundo durante um ataque. Precisamos de um barramento de comunicação assíncrona que suporte:
1. **Garantia de Ordenação:** Eventos de um mesmo ativo (`AssetID`) devem ser processados estritamente na ordem cronológica em que ocorreram.
2. **Deduplicação (Idempotência):** Prevenir que múltiplos alertas repetidos gerem chamadas de API duplicadas.
3. **Event Replay (Retenção Operacional):** Agentes de IA ou analistas de Threat Hunting precisam ser capazes de "reler" eventos do passado recente.
4. **Auditoria Imutável:** Natureza *append-only* dos logs legais.

## 2. Decisão
Decidimos utilizar o ecossistema **Kafka** (implementado via **Redpanda** para menor overhead operacional e dispensa do Zookeeper/JVM) como o Message Broker padrão do GovSec Shield.

## 3. Regras de Implementação
1. **Partition Key = AssetID:** Todos os tópicos de eventos usarão obrigatoriamente `AssetID` como Partition Key para garantir ordenação estrita.
2. **CorrelationKey no Banco:** O Core Platform e os Connectors usarão a `CorrelationKey` (Hash do payload gerado na borda) para verificar no PostgreSQL se a ação já foi tomada (Idempotência at-least-once).
3. **Retenção:** Tópicos como `SecurityEvent` terão retenção operacional (ex: 30 dias). Tópicos de auditoria (`AuditRecorded`) utilizarão políticas de retenção de longo prazo / Tiered Storage.
