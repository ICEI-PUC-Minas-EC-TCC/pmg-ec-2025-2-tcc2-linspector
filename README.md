# LINspector

Ferramenta completa de análise e validação de protocolos LIN (*Local Interconnect Network*) e CAN (*Controller Area Network*) para aplicações automotivas.

## Visão Geral

LINspector é um analisador profissional de logs de comunicação automotiva que realiza validação aprofundada de conformidade de protocolo, análise de timing, verificação de integridade de dados e validação de mapeamento de sinais gateway. A ferramenta gera relatórios HTML detalhados com estatísticas, gráficos e identificação de problemas.

## Funcionalidades

### Análise de Protocolo LIN
- Parsing completo de arquivos LDF (LIN Description File)
- Validação de checksums LIN (Classic e Enhanced)
- Verificação de Protected Identifier (PID) com bits de paridade
- Análise de camada física:
  - Validação de bit rate e tolerância
  - Verificação de break field (duração e formato)
  - Validação de sync field (0x55)
  - Análise de break delimiter
- Verificação de aderência a schedule tables
- Detecção de violações de timing
- Análise de jitter entre frames

### Análise de Protocolo CAN
- Parsing de arquivos DBC (CAN Database)
- Suporte a CAN 2.0A (11-bit ID) e 2.0B (29-bit ID)
- Suporte a CAN FD (Flexible Data-rate)
- Extração de sinais com scaling e offset
- Análise de bus load
- Detecção de bit stuffing errors

### Análise de Gateway
- Correlação temporal entre sinais LIN e CAN
- Validação de mapeamento de sinais
- Cálculo de latência de gateway
- Detecção de sinais dessincronizados
- Identificação de valores incompatíveis após mapeamento

### Geração de Relatórios
- Relatórios HTML interativos com CSS estilizado
- Sumário executivo com métricas principais
- Tabelas detalhadas de erros com timestamps
- Estatísticas de sinais (min/max/média/desvio padrão)
- Gráficos de bus load temporal
- Análise de distribuição de timing
- Seções colapsáveis para navegação fácil

## Requisitos

### Python
- Python 3.7 ou superior

### Bibliotecas Python
dataclasses (incluído no Python 3.7+)
re (biblioteca padrão)
statistics (biblioteca padrão)
datetime (biblioteca padrão)
collections (biblioteca padrão)

Nenhuma dependência externa é necessária.

## Uso

### Uso Básico

`python linspector.py --ldf network.ldf --dbc powertrain.dbc --log session.asc --output report.html`

### Configuração Avançada

# Configurações customizadas
```
config = {
    'bit_rate': 19200,
    'bit_rate_tolerance': 0.02,
    'gateway_time_window': 0.010,
    'schedule_tolerance': 0.0005,
    'max_jitter': 0.001
}

results = linspector.process_log_file(
    ldf_path='network.ldf',
    dbc_path='powertrain.dbc',
    log_path='test.asc',
    config=config
)
```
## Formatos de Arquivo Suportados

### Arquivos de Configuração
- **LDF**: LIN Description File (formato padrão LIN Consortium)
- **DBC**: CAN Database (formato Vector)

### Formato de Log Esperado
# Formato LIN
`0.123456 Rx 1 0x12 8 01 02 03 04 05 06 07 08`

# Formato CAN
`0.123456 1 0x123 Rx d 8 01 02 03 04 05 06 07 08`

# CAN FD
`0.123456 1 0x123 Rx f 64 01 02 03 ... FF`

## API Reference

### Funções Principais

#### `parse_ldf(ldf_path: str) -> LDFData`
Faz parsing de arquivo LDF e retorna estrutura com frames e sinais.

#### `parse_dbc(dbc_path: str) -> Tuple[List[DBCMessage], Dict]`
Faz parsing de arquivo DBC e retorna mensagens e atributos.

#### `parse_log_file(log_path: str) -> List[LogEntry]`
Faz parsing de arquivo de log e retorna lista de entradas.

#### `calculate_lin_checksum(frame_id: int, data: List[int], checksum_type: str) -> int`
Calcula checksum LIN (classic ou enhanced).

#### `validate_physical_layer(log_entries: List[LogEntry], expected_bit_rate: int) -> Dict`
Valida parâmetros de camada física LIN.

#### `validate_schedule_adherence(log_entries: List[LogEntry], schedule: Dict, tolerance: float) -> List`
Valida aderência ao schedule table.

#### `analyze_gateway_mapping(lin_log, can_log, ldf_data, dbc_messages, mapping_config) -> Dict`
Analisa correlação e mapeamento de sinais entre LIN e CAN.

#### `calculate_bus_load(log_entries: List[LogEntry], window_size: float, bit_rate: int) -> List[Tuple]`
Calcula porcentagem de utilização do barramento ao longo do tempo.

#### `generate_html_report(analysis_results: Dict, output_path: str) -> None`
Gera relatório HTML completo com todos os resultados.

#### `process_log_file(ldf_path, dbc_path, log_path, output_path, config) -> Dict`
Função principal que executa análise completa e gera relatório.

## Interpretação de Resultados

### Tipos de Erros

1. **Checksum Errors**: Indicam corrupção de dados ou problemas de implementação
2. **Timing Violations**: Frames fora do timing esperado, pode causar perda de sincronização
3. **Physical Layer Errors**: Problemas de hardware ou configuração incorreta de bit rate
4. **Schedule Violations**: Master não está seguindo o schedule definido
5. **Gateway Mismatches**: Sinais não estão sendo corretamente mapeados entre redes
---

**Nota**: Este projeto é fornecido "como está", sem garantias. Use por sua própria conta e risco em ambientes de produção.

