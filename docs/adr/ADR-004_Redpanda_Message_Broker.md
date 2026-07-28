# ADR 004: Escolha do Redpanda como broker de eventos

## Status
Aceito

## Contexto
O **GovSec Shield** opera em uma arquitetura desacoplada Orientada a Eventos (EDA). Pipelines de segurança em tempo real (como agentes Wazuh, firewalls municipais, coletores Zabbix e scanners de portas) transmitem rajadas contínuas e picos imprevistos de milhares de eventos por segundo.

O broker de eventos é a espinha dorsal de transporte de dados da plataforma e deve atender a quatro requisitos críticos:
1. **Garantia de Ordenação por Ativo:** Eventos gerados para o mesmo ativo (`AssetID`) ou tenant devem ser processados estritamente na sequência cronológica em que foram emitidos.
2. **Alta Throughput e Baixa Latência:** Processamento de milhares de eventos por segundo sem introduzir gargalos nos pipelines de ingestão do Risk Engine e agentes de IA.
3. **Eficiência Operacional em Nuvem / On-Premise Governamental:** Minimizar o consumo de memória RAM, CPU e descartar dependências pesadas de infraestrutura (como JVM/Java e ZooKeeper/KRaft complexo), viabilizando implantação leve em prefeituras pequenas ou data centers estaduais.
4. **Compatibilidade Nativa com a API do Apache Kafka:** Permitir o uso dos clientes e ecossistema padrão da indústria no Python (`aiokafka`).

## Decisão
Decidimos adotar o **Redpanda** (motor compatível com a API Apache Kafka escrito do zero em C++) como o Message Broker padrão da arquitetura Orientada a Eventos do GovSec Shield.

### Padrões de Uso Arquitetural:
1. **Tópicos e Particionamento (`Partition Key = AssetID / TenantID`):** Todos os eventos de segurança usam obrigatoriamente o `AssetID` ou `TenantID` como Partition Key para garantir roteamento para a mesma partição e ordenação estrita.
2. **Fallback Transparente In-Memory para Desenvolvimento/Testes:** A classe `EventBus` (`src/core/infrastructure/messaging/event_bus.py`) utiliza `aiokafka` quando conectada ao cluster Redpanda e fallback transparente In-Memory para ambiente de testes automatizados (`pytest`).
3. **Retenção Configurável por Tópico:** Tópicos operacionais de telemetria (ex: `security.logs.ingested`) usam retenção curta/média (ex: 7 a 30 dias), enquanto tópicos de auditoria usam retenção de longo prazo.

## Consequências

### Impactos Positivos:
- **Zero JVM e Zero ZooKeeper:** O Redpanda roda em um único binário C++ nativo escalável via arquitetura Thread-per-Core (Seastar), reduzindo o consumo de memória em até 80% comparado ao Apache Kafka tradicional.
- **Compatibilidade 100% Kafka API:** Permite o uso de bibliotecas Python consagradas (`aiokafka`, `confluent-kafka`) sem necessidade de adaptadores proprietários.
- **Boot e Latência Extremamente Baixos:** Inicialização em milissegundos, essencial para ambientes de desenvolvimento local via Docker Compose (`docker/compose/docker-compose.yml`) e pipelines de CI/CD.
- **Desempenho Determinístico de Disco:** Otimização direta com I/O assíncrono Direct I/O Bypass.

### Impactos Negativos:
- **Tecnologia Mais Recente:** Embora madura e compatível com a API do Kafka, possui comunidade menor de suporte em relação ao Apache Kafka tradicional mantido pela Apache Foundation há mais de uma década.
- **Licenciamento Enterprise para Recursos Avançados:** Recursos avançados de Tiered Storage em nuvens proprietárias podem requerer licença comercial Redpanda Enterprise se expandidos além da versão comunitária.

## Alternativas Consideradas

1. **Apache Kafka Tradicional (Java/JVM):**
   - *Motivo da Rejeição:* Alto consumo de recursos de memória (JVM heap tuning) e complexidade de gerenciar instâncias ZooKeeper ou clusters KRaft pesados para prefeituras de menor porte.
2. **RabbitMQ:**
   - *Motivo da Rejeição:* Embora excelente para filas de mensagens tradicionais (AMQP), não possui suporte nativo eficiente a log ordenado persistente com *event replay* arbitrário como a API Kafka.
3. **NATS JetStream:**
   - *Motivo da Rejeição:* Excelente desempenho, porém ecossistema de integração e ferramentas de observabilidade/CDC de terceiros menos difundidas que o padrão Kafka na área de segurança cibernética.
