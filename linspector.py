"""
LINspector - Analisador de Protocolos LIN e CAN

Este módulo fornece funcionalidades completas para análise de logs de comunicação
LIN (Local Interconnect Network) e CAN (Controller Area Network).

Funcionalidades principais:
- Parsing de arquivos LDF (LIN Description File) e DBC (CAN Database)
- Validação de checksums LIN (classic e enhanced)
- Verificação de timing e aderência a schedules
- Análise de camada física (bit rate, break field, sync field)
- Validação de mapeamento de sinais gateway
- Geração de relatórios HTML com estatísticas detalhadas
"""
import io
import os
import re
import sys
import json
import base64
import argparse
import matplotlib
import collections
from html import escape
from hashlib import md5
import matplotlib.pyplot as plt
from dataclasses import dataclass, field
from collections import defaultdict
from typing import List, Union, Iterator, Optional, Dict, Tuple, Any, TypedDict
matplotlib.use('Agg')
@dataclass
class LDFSignal:
    """
    Representa um sinal definido em um arquivo LDF.
    Attributes:
        name (str): Nome do sinal
        size (int): Tamanho em bits
        init_value (int): Valor inicial do sinal
        publisher (str): Nó ECU que publica o sinal
        offset (int): Posição do bit inicial no frame
    """
    name: str
    length: int
    publisher: str
    subscriber: str
    start_bit: Optional[int] = None
    unit: Optional[str] = None
    factor: float = 1.0
    offset: float = 0.0
    logical_map: Dict[int, str] = field(default_factory=dict)
    encoding_type: str = "physical"
    min_value: Optional[float] = None
    max_value: Optional[float] = None
@dataclass
class LDFFrame:
    """
    Representa um frame LIN definido em um arquivo LDF.
    
    Attributes:
        name (str): Nome do frame
        frame_id (int): Identificador do frame (0-63)
        publisher (str): Nó que publica o frame
        size (int): Tamanho do frame em bytes (1-8)
        signals (List[LDFSignal]): Lista de sinais contidos no frame
    """

    name: str
    id: Optional[int] = None
    publisher: Optional[str] = None
    dlc: Optional[int] = None
    signals: List[LDFSignal] = field(default_factory=list)
    frame_type: str = "standard"
    associated_frames: List[str] = field(default_factory=list)
@dataclass
class LDFData:
    nodes: Dict[str, Any]
    frames: Dict[str, LDFFrame]
    schedules: Dict[str, List[Dict[str, Union[str, int]]]]
    signal_encoding: Dict[str, Dict[str, float]] = field(default_factory=dict)
@dataclass
class DBCSignal:
    name: str
    start_bit: Optional[int] = None
    length: Optional[int] = None
    factor: float = 1.0
    offset: float = 0.0
    unit: Optional[str] = None
    is_big_endian: bool = True
    is_signed: bool = False
    logical_map: Dict[int, str] = field(default_factory=dict)
    is_multiplexer_switch: bool = False
    multiplexer_value: Optional[int] = None
    min_value_defined: Optional[float] = None
    max_value_defined: Optional[float] = None
@dataclass
class DBCMessage:
    id: int
    name: str
    dlc: int
    node_name: Optional[str]
    signals: List[DBCSignal]
    attributes: Dict[str, Any] = field(default_factory=dict)
    cycle_time: Optional[int] = None
    start_delay_time: Optional[int] = None
    nr_of_repetition: Optional[int] = None
    cycle_time_fast: Optional[int] = None
    delay_time: Optional[int] = None
@dataclass
class LogEntry:
    """
    Representa uma entrada individual do log de comunicação.
    
    Attributes:
        timestamp (float): Timestamp em segundos
        bus_type (str): Tipo de bus ('LIN' ou 'CAN')
        direction (str): Direção da mensagem ('Rx' ou 'Tx')
        frame_id (int): ID do frame/mensagem
        data (List[int]): Dados em bytes
        channel (int): Canal de comunicação
        dlc (int): Data Length Code
        flags (str): Flags adicionais da mensagem
    """
    timestamp: float
    channel: str
    frame_id: str
    frame_id_int: int
    type: str
    data: List[int]
    raw_line: str
    declared_checksum: Optional[int] = None
    csm: Optional[str] = None
    physical_metadata: Optional[Dict[str, str]] = None
    event_channel: Optional[int] = None
    full_time_tbit: Optional[float] = None
    header_time_tbit: Optional[float] = None
class AggregatedMessageData(TypedDict):
    name: str
    id: int
    signals_dict: Dict[str, DBCSignal]
    dlc: Optional[int]
    node_name: Optional[str]
    attributes: Dict[str, Any]
# PADRÕES DE EXPRESSÕES REGULARES PARA PARSING DE LOGS
LIN_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+(?P<id>[0-9A-Fa-f]+)\s+(?P<type>\w+)(?:\s+(?P<dl>\d+))?(?P<data>(?:\s+[0-9A-Fa-f]{2}){0,})(?:.*?checksum\s*=\s*(?P<checksum>[0-9A-Fa-f]{2}))?(?:.*?header\s*time\s*=\s*(?P<header_time>\s*\d+))?(?:.*?full\s*time\s*=\s*(?P<full_time>\s*\d+))?(?:.*?SOF\s*=\s*(?P<sof>\s*\d+\.\d+))?(?:.*?BR\s*=\s*(?P<br>\s*\d+))?(?:.*?break\s*=\s*(?P<break_info>[\d\s]+))?(?:.*?EOH\s*=\s*(?P<eoh>\s*\d+\.\d+))?(?:.*?EOB\s*=\s*(?P<eob>[\d\.\s]+))?(?:.*?EOF\s*=\s*(?P<eof>\s*\d+\.\d+))?(?:.*?RBR\s*=\s*(?P<rbr>\s*\d+))?(?:.*?HBR\s*=\s*(?P<hbr>[\d\.]+))?(?:.*?HSO\s*=\s*(?P<hso>\s*\d+))?(?:.*?RSO\s*=\s*(?P<rso>\s*\d+))?(?:.*?CSM\s*=\s*(?P<csm>\w+))?', re.IGNORECASE)
CANFD_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+CANFD\s+(?P<channel>\d+)\s+(?P<type>\w+)\s+(?P<id>[0-9A-Fa-f]+)(?:\s+(?P<flags>[\w\s]+))?(?:\s+(?P<dl>\d+))?(?P<data>(?:\s+[0-9A-Fa-f]{2}){0,}).*', re.IGNORECASE)
CAN_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+(?P<channel>\d+)\s+(?P<id>[0-9A-Fa-f]+)(?:\s+F)?\s+(?P<type>\w+)(?:\s*d\s*(?P<dl>\d+))?(?P<data>(?:\s+[0-9A-Fa-f]{2}){0,}).*', re.IGNORECASE)
EVENT_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+SleepModeEvent\s+(?P<event_channel>\d+)\s+(?P<detail>.+)', re.IGNORECASE)
SPIKE_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+Spike\s+Rx\s+(?P<detail>.+)', re.IGNORECASE)
TRANSERR_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+(?P<id>[0-9A-Fa-f]+)\s+TransmErr\b.*', re.IGNORECASE)
RCVERR_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+(?P<id>[0-9A-Fa-f]+)?\s*(?:\d+)?\s*RcvError:.*', re.IGNORECASE)
UNEXPECTED_WAKEUP_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+Unexpected wakeup:\s*(?P<detail>.+)(?:.*?SOF\s*=\s*(?P<sof>\s*\d+\.\d+))?(?:.*?BR\s*=\s*(?P<br>\s*\d+\.?\d*))?.*', re.IGNORECASE)
SCHED_CHANGE_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+SchedModChng\s+prior scheduler mode = (?P<prior_mode>\d+), next scheduler mode = (?P<next_mode>\d+), prior scheduler slot = (?P<prior_slot>\d+), next scheduler slot = (?P<next_slot>\d+), first after wake-up = (?P<first_after_wake>\d+)', re.IGNORECASE)
WAKEUP_PATTERN = re.compile(r'^\s*(?P<ts>\d+\.\d+)\s+Li\s+WakeupFrame\s+(?P<type>\w+)(?:\s+(?P<id>[0-9A-Fa-f]+))?(?:\s+(?P<dl>\d+))?(?P<data>(?:\s+[0-9A-Fa-f]{2}){0,})(?:.*?SOF\s*=\s*(?P<sof>\s*\d+\.\d+))?(?:.*?BR\s*=\s*(?P<br>\s*\d+\.?\d*))?(?:.*?LengthCode\s*=\s*(?P<length_code>\s*\d+))?.*', re.IGNORECASE)
DBC_BA_DEF_DEF_RE = re.compile(r'BA_DEF_DEF_\s+"([^"]+)"\s+([^;]+);', re.IGNORECASE)
DBC_BA_NON_OBJECT_SPECIFIC_RE = re.compile(r'BA_\s+"([^"]+)"\s+(?!BO_\s|SG_\s|BU_\s)([^;]+);', re.IGNORECASE)
DBC_BA_RE = re.compile(r'BA_\s+"([^"]+)"\s+(?:BO_\s+(\d+)\s+)?(?:SG_\s+(\d+)\s+([\w\d]+)\s+)?(?:BU_\s+([\w\d]+)\s+)?([^;]+);', re.IGNORECASE)
DBC_BA_SIMPLE_ATTR_RE = re.compile(r'BA_\s+"([^"]+)"\s+([^;]+);')
NODE_BLOCK_RE = re.compile(r'Nodes\s*{(.*?)}', re.IGNORECASE | re.DOTALL)
MASTER_NODE_RE = re.compile(r'Master\s*:\s*([^\s,;]+)\s*,\s*([\d\.]+)\s*ms(?:\s*,\s*([\d\.]+)\s*ms)?', re.IGNORECASE)
SLAVE_NODES_RE = re.compile(r'Slaves\s*:\s*([^;]+)', re.IGNORECASE)
SIGNAL_DEF_RE = re.compile(r'\s*(\w+)\s*:\s*(\d+)\s*,\s*\d+\s*,\s*(\w+)(?:\s*,\s*([\w\s,]+))?\s*;', re.IGNORECASE)
ENCODING_TYPE_BLOCK_RE = re.compile(r'Signal_encoding_types\s*{(.*?)}\s*(?:Node_attributes|Schedule_tables|$)', re.IGNORECASE | re.DOTALL)
ENCODING_CHUNK_RE = re.compile(r'(\w+)\s*{(.*?)}', re.IGNORECASE | re.DOTALL)
PHYSICAL_VALUE_RE = re.compile(r'physical_value\s*,\s*\d+\s*,\s*\d+\s*,\s*([\d\.\-eE]+)\s*,\s*([\d\.\-eE]+)\s*,\s*"([^"]*)"', re.IGNORECASE)
LOGICAL_VALUE_RE = re.compile(r'logical_value\s*,\s*(\d+)\s*,\s*"([^"]+)"', re.IGNORECASE)
SIGNAL_REPR_BLOCK_RE = re.compile(r'Signal_representation\s*{(.*?)}', re.IGNORECASE | re.DOTALL)
SIGNAL_REPR_LINE_RE = re.compile(r'\s*(\w+)\s*:\s*([^;]+);', re.IGNORECASE)
FRAME_BLOCK_RE = re.compile(r'Frames\s*{(.*?)}\s*(?:Diagnostic_frames|Schedule_tables|Signal_encoding_types|Node_attributes|$)', re.IGNORECASE | re.DOTALL)
FRAME_DEF_RE = re.compile(r'(\w+)\s*:\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*(\w+)\s*,\s*(\d+)\s*{([^}]*)}', re.IGNORECASE | re.DOTALL)
FRAME_SIG_RE = re.compile(r'\s*(\w+)\s*,\s*(\d+)\s*;', re.IGNORECASE)
DIAG_FRAME_BLOCK_RE = re.compile(r'Diagnostic_frames\s*{(.*?)}\s*(?=(\w+\s*{)|$)', re.IGNORECASE | re.DOTALL)
DIAG_FRAME_DEF_RE = re.compile(r'(\w+)\s*:\s*(0x[0-9A-Fa-f]+|\d+)\s*{([^}]*)}', re.IGNORECASE | re.DOTALL)
SCHEDULE_TABLE_BLOCK_RE = re.compile(r'Schedule_tables\s*{(.*?)}\s*$', re.IGNORECASE | re.DOTALL)
SCHEDULE_TABLE_DEF_RE = re.compile(r'(\w+)\s*{\s*(.*?)\s*}', re.IGNORECASE | re.DOTALL)
SCHEDULE_ENTRY_RE = re.compile(r'(\w+)\s+delay\s+(\d+)\s*ms\s*;', re.IGNORECASE)
DBC_VAL_RE = re.compile(r'VAL_\s+(\d+)\s+(\w+)\s+((?:\s*\d+\s+"[^"]+"\s*)+);')
MSG_DEF_RE = re.compile(r'BO_\s+(\d+)\s+(\w+)\s*:\s*(\d+)\s+([\w\-\_]+)', re.IGNORECASE)
DBC_SIG_RE = re.compile(r'\s*SG_\s+(\w+)\s*([mM]\d*)?\s*:\s*(\d+)\|(\d+)@(\d)([\+\-])\s+\(([\d\.\-eE]+),([\d\.\-eE]+)\)\s+\[([\d\.\-eE]+)\|([\d\.\-eE]+)\]\s+"([^"]*)"\s+([\w\s,]+)', re.IGNORECASE)
PHYSICAL_ERROR_LABELS = {'baudrate_deviation':'Baudrate Deviation','break_field_error_too_short':'Break Field Too Short','break_field_error_too_long':'Break Field Too Long','delimiter_duration_error':'Delimiter Field Duration Mismatch','header_duration_error':'Header Duration Mismatch','frame_duration_error':'Frame Duration Mismatch','byte_timing_error':'Byte Interval Mismatch','ifs_error_too_short':'Inter-Frame Spacing Too Short','hso_duration_error':'Header Sync Field Offset/Duration Error','rso_duration_error':'Response Sync Field Offset/Duration Error'}
COMMA_OUTSIDE_BRACES = re.compile(r',(?![^{}]*\})')
DBC_SIG_RE_SIMPLE = re.compile(r'\s*SG_\s+(\w+)\s*([mM]\d*)?\s*:\s*(\d+)\|(\d+)@(\d)([\+\-])\s+\(([\d\.\-eE]+),([\d\.\-eE]+)\)\s+\[.*?\]\s+"([^"]*)"', re.IGNORECASE)
DBC_VAL_RE = re.compile(r'VAL_\s+(\d+)\s+(\w+)\s+((?:\s*\d+\s+"[^"]+"\s*)+);', re.IGNORECASE)
VAL_PAIR_RE = re.compile(r'(\d+)\s+"([^"]+)"')
LIN_INACTIVITY_THRESHOLD_S = 0.5
# CONSTANTES DE CONFIGURAÇÃO E THRESHOLDS DE VALIDAÇÃO
DEFAULT_PHYSICAL_MASTER_SYNC_BYTE_BITS = 24
DEFAULT_PHYSICAL_SLAVE_SYNC_BYTE_BITS = 14
PHYSICAL_COMPARISON_EPSILON = 1e-6
DEFAULT_LIN_BAUDRATE = 19200
DEFAULT_PHYSICAL_BAUDRATE_TOLERANCE_PERC = 2.0
DEFAULT_PHYSICAL_BREAK_MIN_BITS = 13
DEFAULT_PHYSICAL_BREAK_MAX_BITS = 18
DEFAULT_PHYSICAL_BREAK_ABS_TOLERANCE_US = 50.0
DEFAULT_PHYSICAL_TIMING_RELATIVE_TOLERANCE_FACTOR = 0.1
DEFAULT_SCHEDULE_MIN_ABSOLUTE_TOLERANCE_S = 0.005
DEFAULT_PHYSICAL_MIN_ABSOLUTE_TOLERANCE_S = DEFAULT_SCHEDULE_MIN_ABSOLUTE_TOLERANCE_S
DEFAULT_PHYSICAL_IFS_MIN_BITS = 3
DEFAULT_SUMMARY_LIMIT = 10
SCRIPT_NAME = "LINSpector"
SCRIPT_VERSION = "0.5.0"
DEFAULT_GATEWAY_TOLERANCE_S = 0.022
DEFAULT_BUS_LOAD_WINDOW_S = 1.0
LINSPECTOR_CSS = "<style>:root {--bg-color: #f8f9fa; --text-color: #212529; --text-secondary-color: #495057; --accent-color: #059669; --border-color: #dee2e6; --header-bg: #ffffff; --header-border: #ced4da; --table-header-bg: #e9ecef; --table-row-hover-bg: #dde6f0; --code-bg: #e9ecef; --details-bg: #ffffff; --summary-bg: #f1f3f5; --summary-hover-bg: #e9ecef; --summary-open-bg: #343a40; --summary-open-text: #ffffff; --status-ok-text: #198754; --status-warn-text: #fd7e14; --status-ko-text: #dc3545;}@media (prefers-color-scheme: dark) {:root {--bg-color: #121212; --text-color: #e8e6e3; --text-secondary-color: #adb5bd; --accent-color: #34d399; --border-color: #343a40; --header-bg: #1c1c1c; --header-border: #343a40; --table-header-bg: #2c2c2e; --table-row-hover-bg: #3a3a3c; --code-bg: #2c2c2e; --details-bg: #1c1c1c; --summary-bg: #2c2c2e; --summary-hover-bg: #3a3a3c; --summary-open-bg: #065f46; --summary-open-text: #ffffff; --status-ok-text: #28a745; --status-warn-text: #ffc107; --status-ko-text: #f04a5f;} tbody tr:nth-child(even){ background-color: #1a1a1a; }}body {font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, Ubuntu, sans-serif; margin: 0; padding: 0 2rem 2rem 2rem; line-height: 1.6; font-size: 16px; background-color: var(--bg-color); color: var(--text-color);} .report-header {display: flex; justify-content: center; align-items: center; gap: 1em; background: var(--header-bg); border-bottom: 1px solid var(--border-color); padding: 1.2em 1.5em; margin: 0 -2rem 2.5rem -2rem; font-size: 1.1em; position: sticky; top: 0; z-index: 10; box-shadow: 0 2px 4px rgba(0,0,0,0.05);} .report-title {font-size: 1.25em; font-weight: 600;} .report-meta {color: var(--text-secondary-color);} h1, .main-title {font-size: 2.2rem; color: var(--text-color); border-left: 5px solid var(--accent-color); padding: .6em 1em; margin: 2rem 0 1.5rem 0; background: var(--summary-bg); font-weight: 700; letter-spacing: .01em;} h2 {font-size: 1.6rem; color: var(--text-color); border-bottom: 2px solid var(--border-color); padding-bottom: .3em; margin: 2.5rem 0 1.5rem 0; font-weight: 600;} h3 {font-size: 1.3rem; color: var(--text-color); margin: 2rem 0 1rem 0; font-weight: 600;} h4 {font-size: 1.1rem; color: var(--text-color); margin: 1.5rem 0 .8rem 0; font-weight: 600;} table {border-collapse: collapse; width: 100%; margin-bottom: 2rem; border: 1px solid var(--border-color); box-shadow: 0 1px 3px rgba(0,0,0,0.04);} th, td {padding: .75rem 1rem; text-align: left; border-bottom: 1px solid var(--border-color);} th {background: var(--table-header-bg); font-weight: 600; text-transform: uppercase; font-size: .8em; letter-spacing: .05em;} tbody tr:hover {background-color: var(--table-row-hover-bg);} details {margin: 1rem 0; border: 1px solid var(--border-color); background-color: var(--details-bg); overflow: hidden;} summary {padding: 1rem 1.2rem; cursor: pointer; font-weight: 600; background-color: var(--summary-bg); color: var(--text-color); display: flex; align-items: center; transition: background-color 0.2s ease-in-out; font-size: 1.1em; list-style: none;} summary::-webkit-details-marker {display: none;} summary:hover {background-color: var(--summary-hover-bg);} summary::before {content: '▶'; margin-right: .8em; font-size: .8em; color: var(--text-secondary-color); transition: transform 0.2s ease-in-out;} details[open] > summary {background-color: var(--summary-open-bg); color: var(--summary-open-text); border-bottom: 1px solid var(--border-color);} details[open] > summary::before {transform: rotate(90deg); color: var(--summary-open-text);} details > :not(summary) {padding: 1.5rem;} code, .id-badge {font-family: \"SF Mono\", \"Fira Mono\", \"Consolas\", \"Menlo\", monospace; font-size: 0.9em; background-color: var(--code-bg); color: var(--text-color); padding: .2em .4em;} .status-ok {color: var(--status-ok-text); font-weight: 700;} .status-warn {color: var(--status-warn-text); font-weight: 700;} .status-ko {color: var(--status-ko-text); font-weight: 700;} .status-na {color: var(--text-secondary-color); font-style: italic; font-weight: 500;} .status-info {color: var(--accent-color); font-weight: 700;}</style>"
def _generate_bus_load_plot_base64(bus_load_data_percent: list, window_size_s: float) -> str:
    if not bus_load_data_percent:
        return ""
    try:
        try:
            plt.style.use('seaborn-v0_8-whitegrid')
        except OSError:
            plt.style.use('ggplot')
        fig, ax = plt.subplots(figsize=(10, 2.5), dpi=90)
        time_axis = [i * window_size_s for i in range(len(bus_load_data_percent))]
        ax.plot(time_axis, bus_load_data_percent, color='#059669', linewidth=1.2, label='Bus Load')
        ax.fill_between(time_axis, bus_load_data_percent, color='#059669', alpha=0.1)
        avg_load = sum(bus_load_data_percent) / len(bus_load_data_percent) if bus_load_data_percent else 0
        max_load = max(bus_load_data_percent) if bus_load_data_percent else 0
        ax.axhline(y=avg_load, color='#E67E22', linestyle='--', linewidth=1, label=f'Avg: {avg_load:.2f}%')
        ax.axhline(y=max_load, color='#D9534F', linestyle=':', linewidth=1, label=f'Peak: {max_load:.2f}%')
        ax.set_ylabel('Bus Load (%)', fontsize=10)
        ax.set_xlabel(f'Time (s)', fontsize=10)
        ax.set_ylim(0, 105)
        ax.set_xlim(0, time_axis[-1] if time_axis else 1)
        ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=3, fancybox=True, shadow=False, fontsize='small')
        ax.tick_params(axis='both', which='major', labelsize=8)
        fig.tight_layout(pad=0.5)
        buf = io.BytesIO()
        fig.savefig(buf, format='png')
        plt.close(fig)
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        return f"data:image/png;base64,{img_base64}"
    except Exception as e:
        print(f"Warning: Could not generate LIN bus load plot. Reason: {e}")
        return ""
def smart_split(rhs: str) -> list[str]:
    return [tok.strip() for tok in COMMA_OUTSIDE_BRACES.split(rhs) if tok.strip()]
def calculate_pid(frame_id: int) -> int:
    if not (0 <= frame_id <= 0x3F): raise ValueError(f"Frame ID {frame_id} (0x{frame_id:X}) out of range for PID (0-63).")
    id_bits = frame_id & 0x3F
    p0 = ((id_bits >> 0)&1)^((id_bits >> 1)&1)^((id_bits >> 2)&1)^((id_bits >> 4)&1)
    p1 = (~(((id_bits >> 1)&1)^((id_bits >> 3)&1)^((id_bits >> 4)&1)^((id_bits >> 5)&1)))&1
    return (id_bits | (p0 << 6) | (p1 << 7)) & 0xFF
def convert_signal_value(raw_value: int, factor: float = 1.0, offset: float = 0.0) -> float:
    return (raw_value * factor) + offset
def parse_ldf(ldf_path: str) -> LDFData:
    """
    Faz parsing de um arquivo LDF (LIN Description File).
    
    O arquivo LDF contém a definição completa da rede LIN, incluindo:
    - Configuração de nós (master e slaves)
    - Definição de frames e seus IDs
    - Sinais contidos em cada frame
    - Schedule tables
    - Configurações de diagnóstico
    
    Args:
        ldf_path (str): Caminho para o arquivo .ldf
    
    Returns:
        LDFData: Objeto contendo todos os frames, sinais e configurações
    
    Raises:
        FileNotFoundError: Se o arquivo LDF não for encontrado
        ValueError: Se o formato do arquivo for inválido
    
    Formato esperado do LDF:
        Frames {
            FrameName: frame_id, Publisher, size {
                SignalName, offset;
            }
        }
    """
    try:
        with open(ldf_path, 'r', encoding='utf-8', errors='ignore') as f:
            ldf_content = f.read()
    except FileNotFoundError:
        raise
    except Exception as e:
        raise IOError(f"Could not read LDF file: {e}") from e
    nodes: Dict[str, Union[str, List[str], float]] = {'slaves': []}
    master_jitter_s = 0.0
    nodes_match = NODE_BLOCK_RE.search(ldf_content)
    if nodes_match:
        nodes_text = nodes_match.group(1)
        master_match = MASTER_NODE_RE.search(nodes_text)
        if master_match:
            master_node_name, timebase_ms_str, jitter_ms_str = master_match.groups()
            nodes['master'] = master_node_name.strip()
            try:
                nodes['master_timebase_s'] = float(timebase_ms_str.replace(',', '.')) / 1000.0
            except ValueError:
                pass
            if jitter_ms_str:
                try:
                    master_jitter_s = float(jitter_ms_str.replace(',', '.')) / 1000.0
                except ValueError:
                    pass
            else:
                pass
        nodes['master_jitter_s'] = master_jitter_s
        slaves_match = SLAVE_NODES_RE.search(nodes_text)
        if slaves_match:
            nodes['slaves'] = [s.strip() for s in slaves_match.group(1).split(',') if s.strip()]
    else:
        raise ValueError("LDF parsing failed: Nodes section not found.")
    signals_base: Dict[str, LDFSignal] = {}
    signals_raw = _extract_block(ldf_content, 'Signals')
    if signals_raw is None:
        signals_raw = ''
    signal_lines = [ln.strip() for ln in signals_raw.splitlines() if ln.strip() and not ln.strip().startswith('//')]
    for line in signal_lines:
        if ':' not in line:
            continue
        name, rhs = line.split(':', 1)
        name = name.strip()
        rhs  = rhs.rstrip(' ;')
        tokens = smart_split(rhs)
        if not tokens:
            continue
        size_bits = int(tokens[0])
        if tokens[1][0].isalpha():
            init_value  = None
            publisher   = tokens[1]
            subscribers = tokens[2:]
        else:
            init_value  = tokens[1]
            publisher   = tokens[2]
            subscribers = tokens[3:]
        subs = [s.strip() for s in subscribers if s.strip()]
        signals_base[name] = LDFSignal(
            name=name,
            length=size_bits,
            publisher=publisher,
            subscriber=subs[0] if subs else '',
        )
        signals_base[name].encoding_type = 'byte_array' if (init_value or '').startswith('{') else 'physical'
    signal_encoding_details: Dict[str, Dict] = {}
    encoding_match = ENCODING_TYPE_BLOCK_RE.search(ldf_content)
    if encoding_match:
        encoding_chunks = ENCODING_CHUNK_RE.findall(encoding_match.group(1))
        for encoding_name, body in encoding_chunks:
            details: Dict[str, Any] = {}
            phys_match = PHYSICAL_VALUE_RE.search(body)
            if phys_match:
                factor_str, offset_str, unit = phys_match.groups()
                try:
                    details['factor'] = float(factor_str.replace(',', '.'))
                    details['offset'] = float(offset_str.replace(',', '.'))
                    details['unit'] = unit
                    min_max_match = re.search(r'\[([\d\.\-eE]+)\|([\d\.\-eE]+)\]', body)
                    if min_max_match:
                        details['min_value'] = float(min_max_match.group(1).replace(',', '.'))
                        details['max_value'] = float(min_max_match.group(2).replace(',', '.'))
                except ValueError:
                    pass
            logical_entries = LOGICAL_VALUE_RE.findall(body)
            if logical_entries:
                logical_map = {}
                for raw_str, label in logical_entries:
                    try:
                        logical_map[int(raw_str)] = label
                    except ValueError:
                         pass
                if logical_map:
                    details['logical_map'] = logical_map
                details['encoding_type'] = 'hybrid' if phys_match and 'factor' in details else 'logical'
            elif phys_match and 'factor' in details:
                details['encoding_type'] = 'physical'
            else:
                 details['encoding_type'] = 'unknown'
            if details:
                signal_encoding_details[encoding_name] = details
    else:
        pass
    signal_objs = []
    missing = []
    signal_to_encoding_map: Dict[str, str] = {}
    deferred_warnings: List[Tuple[str, str]] = []
    representation_match = SIGNAL_REPR_BLOCK_RE.search(ldf_content)
    if representation_match:
        for line in representation_match.group(1).splitlines():
            match = SIGNAL_REPR_LINE_RE.match(line)
            if match:
                encoding_name, signals_str = match.groups()
                if encoding_name in signal_encoding_details:
                    signal_names = [s.strip() for s in signals_str.split(',') if s.strip()]
                    for sig_name in signal_names:
                        sig_obj = signals_base.get(sig_name)
                        if sig_name in signals_base:
                            signal_to_encoding_map[sig_name] = encoding_name
                        else:
                            deferred_warnings.append((sig_name, encoding_name))
                        if sig_obj:
                            signal_objs.append(sig_obj)
                        else:
                            missing.append(sig_name)
                else:
                    pass
    else:
        pass
    frames: Dict[str, LDFFrame] = {}
    frames_match = FRAME_BLOCK_RE.search(ldf_content)
    if frames_match:
        frame_defs = FRAME_DEF_RE.findall(frames_match.group(1))
        for fname, fid_str, publisher, dlc_str, sigs_text in frame_defs:
            frame_signals: List[LDFSignal] = []
            try:
                frame_id = int(fid_str, 0)
                frame_dlc = int(dlc_str)
            except ValueError:
                continue
            for sig_line in sigs_text.splitlines():
                sig_match = FRAME_SIG_RE.match(sig_line)
                if sig_match:
                    sig_name = sig_match.group(1).strip()
                    start_bit_str = sig_match.group(2)
                    if sig_name in signals_base:
                        base_sig_info = signals_base[sig_name]
                        encoding_name = signal_to_encoding_map.get(sig_name)
                        encoding_details = signal_encoding_details.get(encoding_name, {}) if encoding_name else {}
                        try:
                            signal_instance = LDFSignal(
                                name=sig_name,
                                length=base_sig_info.length,
                                publisher=base_sig_info.publisher,
                                subscriber=base_sig_info.subscriber,
                                start_bit=int(start_bit_str),
                                factor=encoding_details.get('factor', 1.0),
                                offset=encoding_details.get('offset', 0.0),
                                unit=encoding_details.get('unit'),
                                logical_map=encoding_details.get('logical_map', {}),
                                encoding_type=encoding_details.get('encoding_type', 'physical')
                            )
                            frame_signals.append(signal_instance)
                        except ValueError:
                             pass
                    else:
                        pass
            frames[fname] = LDFFrame(fname, frame_id, publisher, frame_dlc, frame_signals)
    else:
        pass
    spor_raw = _extract_block(ldf_content, 'Sporadic_frames')
    if spor_raw:
        for ln in spor_raw.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith('//'):
                continue
            if ':' not in ln:
                continue
            sporadic_frame_name, associated_frames_str = ln.split(':', 1)
            sporadic_frame_name = sporadic_frame_name.strip()
            associated_frame_names = [
                frame_name.strip()
                for frame_name in associated_frames_str.rstrip(' ;').split(',')
                if frame_name.strip() and frame_name.strip() in frames
            ]
            if not associated_frame_names:
                print(f"Warning: Sporadic frame '{sporadic_frame_name}' has no valid associated unconditional frames.")
                continue
            frames[sporadic_frame_name] = LDFFrame(
                name=sporadic_frame_name,
                frame_type='sporadic',
                associated_frames=associated_frame_names
            )
    if missing:
        pass
    event_triggered_frames_raw = _extract_block(ldf_content, 'Event_triggered_frames')
    if event_triggered_frames_raw:
        for line in event_triggered_frames_raw.splitlines():
            line = line.strip()
            if not line or line.startswith('//') or ';' not in line:
                continue
            try:
                event_frame_name_part, details_part = line.split(':', 1)
                event_frame_name = event_frame_name_part.strip()
                details_part = details_part.rstrip(';').strip()
                tokens = [t.strip() for t in details_part.split(',')]
                frame_id_et = None
                associated_frame_names_et = []
                if tokens:
                    try:
                        frame_id_et = int(tokens[0], 0)
                        associated_frame_names_et = [name for name in tokens[1:] if name and name in frames]
                    except ValueError:
                        associated_frame_names_et = [name for name in tokens if name and name in frames]
                        if associated_frame_names_et and frames[associated_frame_names_et[0]].id is not None:
                            pass
                if not associated_frame_names_et:
                    print(f"Warning: Event-triggered frame '{event_frame_name}' has no valid associated unconditional frames or ID.")
                    continue
                frames[event_frame_name] = LDFFrame(
                    name=event_frame_name,
                    id=frame_id_et,
                    publisher=None,
                    dlc=None,
                    signals=[],
                    frame_type='event_triggered',
                    associated_frames=associated_frame_names_et
                )
            except Exception as e:
                print(f"Warning: Could not parse event_triggered_frame line: '{line}'. Error: {e}")
                pass
    diag_match = DIAG_FRAME_BLOCK_RE.search(ldf_content)
    if diag_match:
        diag_defs = DIAG_FRAME_DEF_RE.findall(diag_match.group(1))
        for frame_name, frame_id_str, signals_text_diag in diag_defs:
            try:
                frame_id = int(frame_id_str, 0)
                publisher_diag = None
                dlc_diag = 8
                if frame_id == 0x3C:
                    publisher_diag = nodes.get('master')
                frames[frame_name] = LDFFrame(
                    name=frame_name,
                    id=frame_id,
                    publisher=publisher_diag,
                    dlc=dlc_diag,
                    signals=[],
                    frame_type='diagnostic'
                )
            except ValueError:
                print(f"Warning: Could not parse diagnostic frame ID for '{frame_name}'.")
                pass
    schedules: Dict[str, List[Dict[str, Union[str, int]]]] = {}
    schedule_match = SCHEDULE_TABLE_BLOCK_RE.search(ldf_content)
    if schedule_match:
        schedule_defs = SCHEDULE_TABLE_DEF_RE.findall(schedule_match.group(1))
        for sched_name, sched_body in schedule_defs:
            entries = SCHEDULE_ENTRY_RE.findall(sched_body)
            schedule_entries: List[Dict[str, Union[str, int]]] = []
            valid_schedule = True
            for frame_name, delay_ms_str in entries:
                if frame_name in frames:
                    try:
                        schedule_entries.append({
                            'frame_name': frame_name,
                            'delay_ms': int(delay_ms_str)
                        })
                    except ValueError:
                         valid_schedule = False
                         break
                else:
                    valid_schedule = False
                    break
            if valid_schedule and schedule_entries:
                schedules[sched_name] = schedule_entries
    else:
        pass
        
    nodes['slaves_with_error_signal'] = {}
    node_attributes_content = _extract_block(ldf_content, 'Node_attributes')
    if node_attributes_content:
        response_error_re = re.compile(r'response_error\s*=\s*(\w+)\s*;', re.IGNORECASE)
        node_name_re = re.compile(r'^\s*(\w+)\s*{', re.MULTILINE)
        
        node_matches = list(node_name_re.finditer(node_attributes_content))
        for i, current_match in enumerate(node_matches):
            node_name = current_match.group(1)
            
            start_pos = current_match.end()
            end_pos = node_matches[i+1].start() if i + 1 < len(node_matches) else len(node_attributes_content)
            
            node_body = node_attributes_content[start_pos:end_pos]

            if node_name in nodes.get('slaves', []):
                error_signal_match = response_error_re.search(node_body)
                if error_signal_match:
                    error_signal_name = error_signal_match.group(1)
                    nodes['slaves_with_error_signal'][node_name] = error_signal_name
                    if error_signal_name not in signals_base:
                        print(f"Warning: Response error signal '{error_signal_name}' for node '{node_name}' is defined but not found in the Signals block.")

    if not frames:
        raise ValueError("LDF parsing failed: No frames found.")
    if 'master' not in nodes:
         pass
    ldf_data_obj = LDFData(
        nodes=nodes,
        frames=frames,
        schedules=schedules,
        signal_encoding=signal_encoding_details
    )
    used_signals = {
        sig.name
        for frame in frames.values()
        for sig in frame.signals
    }
    for sig_name, encoding_name in deferred_warnings:
        if sig_name not in used_signals:
            pass
    return ldf_data_obj
def _extract_block(text: str, keyword: str) -> str | None:
    start_match = re.search(rf'{keyword}\s*{{', text, re.IGNORECASE)
    if not start_match:
        return None
    idx = start_match.end()
    depth = 1
    while idx < len(text) and depth:
        if text[idx] == '{':
            depth += 1
        elif text[idx] == '}':
            depth -= 1
        idx += 1
    return text[start_match.end():idx-1] if depth == 0 else None
def load_gateway_map(map_path: str) -> Optional[List[Dict[str, Any]]]:
    try:
        with open(map_path, 'r', encoding='utf-8') as f:
            mappings = json.load(f)
    except FileNotFoundError:
        print(f"Error: Gateway map file not found: {map_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Could not decode JSON from gateway map file {map_path}: {e}")
        return None
    except Exception as e:
        print(f"Error: Could not read gateway map file {map_path}: {e}")
        return None
    if not isinstance(mappings, list):
        print(f"Error: Gateway map content in {map_path} is not a list.")
        return None
    validated_mappings = []
    valid_overall = True
    required_keys = {'source_network', 'source_message', 'source_signal',
                     'target_network', 'target_message', 'target_signal'}
    valid_networks = {'LIN', 'CAN1', 'CAN2', 'CAN3', 'CANFD1', 'CANFD2', 'CANFD3'}
    for i, m in enumerate(mappings):
        current_mapping_valid = True
        if not isinstance(m, dict):
            print(f"Error: Entry {i} in gateway map {map_path} is not a dictionary.")
            valid_overall = False
            continue
        missing_keys = required_keys - m.keys()
        if missing_keys:
            print(f"Error: Entry {i} in gateway map {map_path} is missing required keys: {missing_keys}.")
            current_mapping_valid = False
        for key in required_keys:
            if key in m and not isinstance(m[key], str):
                print(f"Error: Entry {i}, key '{key}' in gateway map {map_path} is not a string.")
                current_mapping_valid = False
        if m.get('source_network') not in valid_networks:
            print(f"Error: Entry {i}, 'source_network' '{m.get('source_network')}' in gateway map {map_path} is invalid.")
            current_mapping_valid = False
        if m.get('target_network') not in valid_networks:
            print(f"Error: Entry {i}, 'target_network' '{m.get('target_network')}' in gateway map {map_path} is invalid.")
            current_mapping_valid = False
        if current_mapping_valid:
            validated_mappings.append(m)
        else:
            valid_overall = False
    if not valid_overall:
         print(f"Warning: Some entries in gateway map {map_path} were invalid. Check logs.")
    if not validated_mappings and not valid_overall :
        return None
    return validated_mappings
def group_equivalent_schedules(
    schedules: Dict[str, List[Dict[str, Union[str, int]]]]
) -> Tuple[Dict[str, List[Dict[str, Union[str, int]]]], Dict[str, str], Dict[str, List[str]]]:
    if not schedules:
        return {}, {}, {}
    hash_to_representative_name: Dict[str, str] = {}
    representative_to_all_grouped_names_map: Dict[str, List[str]] = defaultdict(list)
    original_name_to_representative_name_map: Dict[str, str] = {}
    sorted_original_schedule_names = sorted(schedules.keys())
    for original_name in sorted_original_schedule_names:
        entries = schedules[original_name]
        if not isinstance(entries, list):
            original_name_to_representative_name_map[original_name] = original_name
            representative_to_all_grouped_names_map[original_name] = [original_name]
            continue
        try:
            serialized_content = json.dumps(entries, sort_keys=True)
            content_hash = md5(serialized_content.encode('utf-8')).hexdigest()
            if content_hash not in hash_to_representative_name:
                hash_to_representative_name[content_hash] = original_name
            representative_name = hash_to_representative_name[content_hash]
            original_name_to_representative_name_map[original_name] = representative_name
            representative_to_all_grouped_names_map[representative_name].append(original_name)
        except (TypeError, Exception) as e:
            print(f"Warning: Could not process schedule '{original_name}' for grouping due to error: {e}. Treating as unique.")
            original_name_to_representative_name_map[original_name] = original_name
            representative_to_all_grouped_names_map[original_name] = [original_name]
            continue
    unique_schedules: Dict[str, List[Dict[str, Union[str, int]]]] = {}
    for rep_name in representative_to_all_grouped_names_map.keys():
        unique_schedules[rep_name] = schedules[rep_name]
        representative_to_all_grouped_names_map[rep_name] = sorted(list(set(representative_to_all_grouped_names_map[rep_name])))
    return unique_schedules, original_name_to_representative_name_map, representative_to_all_grouped_names_map
def find_frame_id_for_signal(
    signal_name: str,
    network_type: str,
    ldf_data: LDFData,
    can_dbcs: Dict[str, Dict[int, DBCMessage]],
    warnings: Optional[list] = None,
    context: Optional[dict] = None
) -> Optional[int]:
    if network_type == 'LIN':
        for frame in ldf_data.frames.values():
            if any(s.name == signal_name for s in frame.signals):
                return frame.id
    elif network_type.upper().startswith('CAN'):
        dbc_for_channel = can_dbcs.get(network_type)
        if dbc_for_channel:
            for msg in dbc_for_channel.values():
                if any(s.name == signal_name for s in msg.signals):
                    return msg.id
        else:
            if warnings is not None:
                warnings.append({
                    'signal': signal_name,
                    'network': network_type,
                    'type': 'dbc_missing',
                    'context': context,
                    'message': f"No DBC data found for channel '{network_type}' while searching for signal '{signal_name}'."
                })
    if warnings is not None:
        warnings.append({
            'signal': signal_name,
            'network': network_type,
            'type': 'signal_missing',
            'context': context,
            'message': f"Signal '{signal_name}' not found in any frame/message on network '{network_type}'."
        })
    return None
def update_frame_timing_stats(entry: LogEntry, frame_def: Optional[Union[LDFFrame, DBCMessage]], log_stats: Dict[str, Any]):
    if not frame_def or entry.type.lower() != 'rx':
        return
    channel = entry.channel
    frame_id = entry.frame_id_int
    ts = entry.timestamp
    is_active = log_stats.get('network_cycle_state', {}).get('active', False)
    if not is_active:
        return
    frame_stats = log_stats['frame_timing_stats'][channel][frame_id]
    if frame_stats['frame_name'] is None:
        frame_stats['frame_name'] = frame_def.name
    frame_stats['count'] += 1
    if frame_stats['last_ts'] is not None and frame_stats['last_was_active'] and is_active:
        delta = ts - frame_stats['last_ts']
        max_reasonable_interval = 1.0
        if 0 <= delta <= max_reasonable_interval:
            frame_stats['min_delta'] = min(frame_stats['min_delta'], delta)
            frame_stats['max_delta'] = max(frame_stats['max_delta'], delta)
            frame_stats['sum_delta'] += delta
            frame_stats['delta_count'] += 1
    frame_stats['last_ts'] = ts
    frame_stats['last_was_active'] = is_active
def validate_schedule_order_and_presence(
    entry: LogEntry, ldf_data: LDFData, ldf_id_to_frame_map: Dict[int, LDFFrame],
    log_stats: Dict[str, Any], tolerance_factor: float, min_absolute_tolerance_s: float
):
    """
    Valida aderência ao schedule table definido no LDF.
    
    O LIN master deve transmitir frames de acordo com um schedule predefinido.
    Esta função verifica se os frames aparecem nos tempos esperados.
    
    Args:
        log_entries (List[LogEntry]): Log de comunicação
        schedule (Dict): Schedule table do LDF
            Formato: {'frame_name': {'delay_ms': 10, 'position': 0}, ...}
        tolerance (float): Tolerância em segundos (padrão: 500µs)
    
    Returns:
        List[Dict]: Violações detectadas com timestamp e desvio
    
    Exemplo de schedule:
        Schedule Table: 100ms cycle time
        - Frame1 @ 0ms
        - Frame2 @ 10ms
        - Frame3 @ 25ms
    """
    if entry.type not in ('Rx', 'TransmErr', 'RcvError'):
        return
    current_frame_obj = ldf_id_to_frame_map.get(entry.frame_id_int)
    if not current_frame_obj:
        return
    current_frame_name = current_frame_obj.name
    current_ts = entry.timestamp
    state = log_stats['schedule_runtime_state']
    analysis_log = log_stats['schedule_analysis']
    slot_timing_stats = log_stats['schedule_slot_timing']
    reliability_stats = log_stats['slave_reliability']
    master_node_name = ldf_data.nodes.get('master')

    def _reset_state():
        state.update({
            'active_schedules': [], 'current_index': 0, 'last_event_timestamp': None,
            'cycle_start_timestamp': None, 'cycle_log': [], 'cycle_id': state.get('cycle_id', 0) + 1,
            'has_timing_errors': False
        })
    def _log_cycle_event(event_type: str, details: Dict[str, Any]):
        state['cycle_log'].append({'ts': current_ts, 'type': event_type, 'details': details})
    def _finalize_cycle(status: str):
        if not state.get('cycle_start_timestamp'):
            _reset_state()
            return
        final_schedule_name = state['active_schedules'][0] if len(state['active_schedules']) == 1 else "Ambiguous"
        if state['cycle_log']:
            analysis_log['cycles'].append({
                'id': state['id'], 'schedule_name': final_schedule_name,
                'start_ts': state['cycle_start_timestamp'], 'end_ts': current_ts,
                'status': status, 'events': list(state['cycle_log']),
                'had_timing_errors': state.get('has_timing_errors', False)
            })
        _reset_state()
    def check_and_finalize_if_complete():
        if len(state['active_schedules']) == 1:
            sched_name = state['active_schedules'][0]
            if state['current_index'] >= len(ldf_data.schedules[sched_name]):
                _log_cycle_event('Cycle Completed', {})
                _finalize_cycle("Completed")
                return True
        return False

    while True:
        if not state.get('active_schedules'):
            candidate_schedules = [n for n, s in ldf_data.schedules.items() if s and s[0]['frame_name'] == current_frame_name]
            if candidate_schedules:
                state.update({
                    'active_schedules': sorted(candidate_schedules), 'current_index': 1,
                    'last_event_timestamp': current_ts, 'cycle_start_timestamp': current_ts,
                    'id': state['cycle_id']
                })
                _log_cycle_event('Cycle Start', {'trigger_frame': current_frame_name})
                if check_and_finalize_if_complete(): return
            else:
                analysis_log['global_errors'].append({'ts': current_ts, 'type': 'Intrusion Frame', 'details': {'frame_name': current_frame_name}})
            return

        current_idx = state['current_index']
        expected_frames_info = {}
        for sched_name in state['active_schedules']:
            schedule = ldf_data.schedules[sched_name]
            if current_idx < len(schedule):
                frame_name = schedule[current_idx]['frame_name']
                if frame_name not in expected_frames_info:
                    expected_frames_info[frame_name] = []
                expected_frames_info[frame_name].append(sched_name)

        if not expected_frames_info:
             _finalize_cycle("Aborted")
             continue

        for frame_name, sched_names in expected_frames_info.items():
            frame_def = ldf_data.frames.get(frame_name)
            if frame_def and frame_def.publisher and frame_def.publisher != master_node_name:
                reliability_stats[frame_def.publisher][frame_name]['requests'] += 1

        if current_frame_name in expected_frames_info:
            potential_matches = expected_frames_info[current_frame_name]
            frame_def = ldf_data.frames.get(current_frame_name)
            if frame_def and frame_def.publisher and frame_def.publisher != master_node_name:
                reliability_stats[frame_def.publisher][current_frame_name]['responses'] += 1
            
            jitter_s = ldf_data.nodes.get('master_jitter_s', 0.0)
            for sched_name in potential_matches:
                expected_delay_ms = ldf_data.schedules[sched_name][current_idx]['delay_ms']
                observed_delay_s = current_ts - state['last_event_timestamp']
                observed_delay_ms = observed_delay_s * 1000
                
                slot_key = (sched_name, current_idx)
                stats = slot_timing_stats[slot_key]
                stats['sum_ms'] += observed_delay_ms
                stats['sum_sq_ms'] += observed_delay_ms ** 2
                stats['count'] += 1
                stats['min_ms'] = min(stats['min_ms'], observed_delay_ms)
                stats['max_ms'] = max(stats['max_ms'], observed_delay_ms)
                
                tolerance_abs = max((expected_delay_ms / 1000.0) * tolerance_factor, min_absolute_tolerance_s) + jitter_s
                if not (abs(observed_delay_s - (expected_delay_ms / 1000.0)) <= tolerance_abs):
                    state['has_timing_errors'] = True
                    mismatch_key = (sched_name, current_idx)
                    mismatch_stats = log_stats['schedule_timing_mismatches'][mismatch_key]    
                    mismatch_stats['count'] += 1
                    mismatch_stats['sum_observed_ms'] += observed_delay_ms
                    mismatch_stats['min_observed_ms'] = min(mismatch_stats['min_observed_ms'], observed_delay_ms)
                    mismatch_stats['max_observed_ms'] = max(mismatch_stats['max_observed_ms'], observed_delay_ms)
                    if mismatch_stats['first_ts'] is None:
                        mismatch_stats['first_ts'] = current_ts
                        mismatch_stats['expected_ms'] = expected_delay_ms
                        frame_def = ldf_data.frames.get(current_frame_name)
                        mismatch_stats['frame_name'] = current_frame_name
                        mismatch_stats['publisher'] = frame_def.publisher if frame_def else 'N/A'
                    mismatch_stats['last_ts'] = current_ts
            
            state['active_schedules'] = sorted(potential_matches)
            state['current_index'] += 1
            state['last_event_timestamp'] = current_ts
            if check_and_finalize_if_complete(): return
            break
        else:
            _log_cycle_event('Sequence Mismatch', {'expected': list(expected_frames_info.keys()), 'observed': current_frame_name})
            _finalize_cycle("Aborted")
            continue
    return
def tag(status, text=None):
    s_upper = str(status).upper()
    txt = text if text is not None else s_upper
    css_class = {'OK':'status-ok','KO':'status-ko','WARN':'status-warn','NA':'status-na','INFO':'status-info'}.get(s_upper, 'status-info')
    return f'<span class="{css_class}">{escape(str(txt))}</span>'
def _log_event(log_stats, sched_name, status, reason, current_ts, details=None):
    if details is None:
        details = {}
    summary_log = log_stats.setdefault('schedule_summary', defaultdict(lambda: defaultdict(lambda: {'count': 0, 'first_ts_event': None, 'last_ts_event': None, 'example_details': None})))
    record = summary_log[sched_name][(status, reason)]
    record['count'] += 1
    if record['first_ts_event'] is None:
        record['first_ts_event'] = current_ts
        record['example_details'] = details.copy() if details else {}
    record['last_ts_event'] = current_ts
def detect_inactivity(
    current_timestamp: float,
    last_activity_timestamp: Optional[float],
    is_network_active: bool,
    log_stats: Dict[str, Any]
) -> Optional[float]:
    if not is_network_active:
        return None
    if last_activity_timestamp is not None:
        duration = current_timestamp - last_activity_timestamp
        if duration > LIN_INACTIVITY_THRESHOLD_S:
            log_stats.setdefault('error_summary', {})
            summary = log_stats['error_summary'].setdefault('inactivity', {
                'periods': 0, 'total_duration': 0.0, 'max_duration': 0.0,
                'first_start': None, 'last_end': None
            })
            summary['periods'] += 1
            summary['total_duration'] += duration
            summary['max_duration'] = max(summary['max_duration'], duration)
            if summary['first_start'] is None:
                summary['first_start'] = last_activity_timestamp
            summary['last_end'] = current_timestamp
    return current_timestamp
def _get_comparison_details(
    signal_name: str,
    network_type: str,
    ldf_signals_by_name: Dict[str, LDFSignal],
    dbc_signals_by_name: Dict[str, DBCSignal]
) -> Optional[Dict[str, Any]]:
    signal_info: Optional[Union[LDFSignal, DBCSignal]] = None
    if network_type == 'LIN':
        signal_info = ldf_signals_by_name.get(signal_name)
    elif network_type.startswith('CAN'):
        signal_info = dbc_signals_by_name.get(signal_name)
    if not signal_info:
        return None
    details = {
        'factor': getattr(signal_info, 'factor', 1.0),
        'offset': getattr(signal_info, 'offset', 0.0),
        'logical_map': getattr(signal_info, 'logical_map', {}),
        'is_signed': getattr(signal_info, 'is_signed', False),
        'length': getattr(signal_info, 'length', None),
        'encoding_type': getattr(signal_info, 'encoding_type', 'physical'),
        'unit': getattr(signal_info, 'unit', '')
    }
    return details
def compare_gateway_values(
    source_val_raw: int,
    target_val_raw: int,
    source_details: Dict[str, Any],
    target_details: Dict[str, Any]
) -> Tuple[bool, str]:
    match = False
    comparison_type = "unknown"
    src_map = source_details['logical_map']
    tgt_map = target_details['logical_map']
    src_has_logic = source_val_raw in src_map
    tgt_has_logic = target_val_raw in tgt_map
    if src_has_logic and tgt_has_logic:
        comparison_type = "raw_logical"
        match = (source_val_raw == target_val_raw)
    elif not src_has_logic and not tgt_has_logic:
        comparison_type = "physical"
        processed_src_raw = source_val_raw
        if source_details['is_signed'] and isinstance(source_details['length'], int) and source_details['length'] > 0:
            len_bits = source_details['length']
            sign_bit_mask = 1 << (len_bits - 1)
            if (processed_src_raw & sign_bit_mask):
                processed_src_raw -= (1 << len_bits)
        src_val_phys = (processed_src_raw * source_details['factor']) + source_details['offset']
        processed_tgt_raw = target_val_raw
        if target_details['is_signed'] and isinstance(target_details['length'], int) and target_details['length'] > 0:
            len_bits = target_details['length']
            sign_bit_mask = 1 << (len_bits - 1)
            if (processed_tgt_raw & sign_bit_mask):
                processed_tgt_raw -= (1 << len_bits)
        tgt_val_phys = (processed_tgt_raw * target_details['factor']) + target_details['offset']
        match = abs(src_val_phys - tgt_val_phys) < PHYSICAL_COMPARISON_EPSILON
    else:
        comparison_type = "hybrid_mismatch"
        match = False
    return match, comparison_type
def finalize_network_cycle_stats(log_stats: Dict[str, Any]) -> None:
    state = log_stats.get('network_cycle_state')
    summary = log_stats.get('network_cycle_summary')
    if state and summary and state['active']:
        cycle_details = state['current_cycle_details']
        summary['cycles_incomplete'] += 1
        cycle_details['problem_flags'].add('Incomplete Cycle')
        if not state['first_master_found']:
            summary['cycles_no_master_response'] += 1
            cycle_details['problem_flags'].add('No Master Response')
        cycle_details['end'] = log_stats['log_info'].get('end_time', state['start_time'])
        cycle_details['end_line'] = "Log ended without sleep event"
        is_problematic = 'Incomplete Cycle' in cycle_details['problem_flags'] or \
                         ('Late Master Response' in cycle_details['problem_flags']) or \
                         ('No Master Response' in cycle_details['problem_flags'])
        if is_problematic and summary['example_problem_cycle'] is None:
             summary['example_problem_cycle'] = cycle_details.copy()
        state['active'] = False
        state['start_time'] = None
        state['first_master_time'] = None
        state['first_master_found'] = False
        state['slaves_responded_in_cycle'] = set()
        state['current_cycle_details'] = {}
        state['just_slept'] = False
        state['current_cycle_end_line'] = None
def _write_physical_metrics_table(write_html, log_stats):
    phys_metrics = log_stats.get('physical_metrics')
    if not phys_metrics:
        return
    write_html("<details close><summary>Physical Layer Metrics</summary>")
    write_html("<table><thead><tr><th>Metric</th><th>Unit</th><th>Min</th><th>Max</th><th>Average</th></tr></thead><tbody>")
    def _generate_metric_row(metric_name: str, data_key: str, unit: str, multiplier: float = 1.0, precision: int = 2):
        data = phys_metrics.get(data_key)
        if not data or data.get('count', 0) == 0:
            return f"<tr><td>{metric_name}</td><td>{unit}</td><td>N/A</td><td>N/A</td><td>N/A</td></tr>"
        avg = (data['sum'] / data['count']) * multiplier
        min_val = data['min'] * multiplier if data['min'] != float('inf') else avg
        max_val = data['max'] * multiplier if data['max'] != float('-inf') else avg
        return (f"<tr>"
                f"<td>{metric_name}</td>"
                f"<td>{unit}</td>"
                f"<td>{min_val:.{precision}f}</td>"
                f"<td>{max_val:.{precision}f}</td>"
                f"<td>{avg:.{precision}f}</td>"
                f"</tr>")
    write_html(_generate_metric_row("Measured Baudrate", 'baudrate_values', "bps", 1.0, 1))
    write_html(_generate_metric_row("Header Duration", 'header_duration_values', "ms", 1000, 2))
    write_html(_generate_metric_row("Frame Duration", 'frame_duration_values', "ms", 1000, 2))
    write_html(_generate_metric_row("Header Sync Duration (HSO)", 'hso_values_s', "µs", 1_000_000, 1))
    write_html(_generate_metric_row("Response Sync Duration (RSO)", 'rso_values_s', "µs", 1_000_000, 1))
    write_html("</tbody></table></details>")
def validate_physical_layer(
    entry: LogEntry,
    match_dict: Dict[str, str],
    log_stats: Dict[str, Any],
    ldf_id_to_frame_map: Dict[int, LDFFrame],
    ldf_data: LDFData,
    config: Dict[str, Any]
) -> None:
    """
    Valida parâmetros da camada física LIN.
    
    Verifica:
    1. Bit Rate: Taxa de bits dentro da tolerância (±2%)
    2. Break Field: Duração entre 13-50 bits (mín 650µs @ 19.2kbps)
    3. Sync Field: Sempre 0x55 com 8 bits
    4. Break Delimiter: 1-2 bits entre break e sync
    
    Args:
        log_entries (List[LogEntry]): Entradas de log LIN
        expected_bit_rate (int): Bit rate esperado em bps
    
    Returns:
        Dict com resultados:
        {
            'bit_rate_errors': [(timestamp, measured, expected), ...],
            'break_field_errors': [(timestamp, duration), ...],
            'sync_field_errors': [(timestamp, value), ...],
            'summary': {...}
        }
    """
    if entry.channel != 'LIN' or not match_dict:
        return
    nominal_baudrate = config.get('lin_baudrate', DEFAULT_LIN_BAUDRATE)
    baudrate_tol_perc = config.get('physical_baudrate_tolerance_perc', DEFAULT_PHYSICAL_BAUDRATE_TOLERANCE_PERC)
    break_min_bits = config.get('physical_break_min_bits', DEFAULT_PHYSICAL_BREAK_MIN_BITS)
    break_max_bits = config.get('physical_break_max_bits', DEFAULT_PHYSICAL_BREAK_MAX_BITS)
    break_abs_tol_us = config.get('physical_break_abs_tolerance_us', DEFAULT_PHYSICAL_BREAK_ABS_TOLERANCE_US)
    timing_rel_tol_factor = config.get('physical_timing_relative_tolerance_factor', DEFAULT_PHYSICAL_TIMING_RELATIVE_TOLERANCE_FACTOR)
    min_abs_tol_s = config.get('physical_min_absolute_tolerance_s', DEFAULT_PHYSICAL_MIN_ABSOLUTE_TOLERANCE_S)
    ifs_min_bits = config.get('physical_ifs_min_bits', DEFAULT_PHYSICAL_IFS_MIN_BITS)
    
    physical_errors = log_stats['physical_errors']
    physical_metrics = log_stats['physical_metrics']
    
    master_jitter_s = ldf_data.nodes.get('master_jitter_s', 0.0)
    jitter_effective_s = max(master_jitter_s, min_abs_tol_s)
    bit_duration_s = (1.0 / nominal_baudrate) if nominal_baudrate > 0 else 0.0
    bit_duration_us = bit_duration_s * 1e6
    baudrate_tol_bps = nominal_baudrate * baudrate_tol_perc / 100.0
    frame_id_key = entry.frame_id_int
    
    def log_physical_error(error_type, value_key, details):
        summary = physical_errors[error_type][(frame_id_key, value_key)]
        summary['count'] += 1
        if summary['first_ts'] is None:
            summary['first_ts'] = entry.timestamp
            summary['example_details'] = details
        summary['last_ts'] = entry.timestamp

    for br_key in ['br', 'rbr', 'hbr']:
        if match_dict.get(br_key):
            try:
                actual_br = float(match_dict[br_key])
                physical_metrics['baudrate_values']['min'] = min(physical_metrics['baudrate_values']['min'], actual_br)
                physical_metrics['baudrate_values']['max'] = max(physical_metrics['baudrate_values']['max'], actual_br)
                physical_metrics['baudrate_values']['sum'] += actual_br
                physical_metrics['baudrate_values']['count'] += 1
                if abs(actual_br - nominal_baudrate) > baudrate_tol_bps:
                    log_physical_error('baudrate_deviation', actual_br, {'value': actual_br, 'type': br_key.upper()})
            except ValueError:
                pass

    if match_dict.get('break_info') and bit_duration_us > 0:
        try:
            break_delimiter_values_ns = [float(v) for v in match_dict['break_info'].split()]
            if len(break_delimiter_values_ns) >= 1:
                break_val_ns = break_delimiter_values_ns[0]
                break_val_us = break_val_ns / 1000.0
                nominal_min_break_us = break_min_bits * bit_duration_us
                nominal_max_break_us = break_max_bits * bit_duration_us
                details = {
                    'raw_value_ns': break_val_ns, 'measured_us': break_val_us,
                    'expected_min_us': nominal_min_break_us, 'expected_max_us': nominal_max_break_us,
                    'tolerance_us': break_abs_tol_us, 'bits_min': break_min_bits, 'bits_max': break_max_bits
                }
                if break_val_us < nominal_min_break_us - break_abs_tol_us:
                    log_physical_error('break_field_error_too_short', break_val_us, details)
                elif break_val_us > nominal_max_break_us + break_abs_tol_us:
                    log_physical_error('break_field_error_too_long', break_val_us, details)
            if len(break_delimiter_values_ns) >= 2:
                delimiter_val_ns = break_delimiter_values_ns[1]
                delimiter_val_us = delimiter_val_ns / 1000.0
                expected_delimiter_us = 1 * bit_duration_us
                delimiter_tolerance_us = break_abs_tol_us
                if abs(delimiter_val_us - expected_delimiter_us) > delimiter_tolerance_us:
                    details = {
                        'raw_value_ns': delimiter_val_ns, 'measured_us': delimiter_val_us,
                        'expected_us': expected_delimiter_us, 'tolerance_us': delimiter_tolerance_us,
                        'reason': 'Too long' if delimiter_val_us > expected_delimiter_us else 'Too short', 'bits_expected': 1
                    }
                    log_physical_error('delimiter_duration_error', delimiter_val_us, details)
        except (ValueError, IndexError):
            pass

    if match_dict.get('sof') and match_dict.get('eof'):
        try:
            sof = float(match_dict['sof'])
            eof = float(match_dict['eof'])
            frame_duration_s = eof - sof
            physical_metrics['frame_duration_values']['min'] = min(physical_metrics['frame_duration_values']['min'], frame_duration_s)
            physical_metrics['frame_duration_values']['max'] = max(physical_metrics['frame_duration_values']['max'], frame_duration_s)
            physical_metrics['frame_duration_values']['sum'] += frame_duration_s
            physical_metrics['frame_duration_values']['count'] += 1
            dlc = len(entry.data) if entry.data is not None else 0
            expected_frame_bits = 43 + (dlc * 10)
            expected_frame_duration_s = expected_frame_bits * bit_duration_s
            frame_tolerance_s = max(expected_frame_duration_s * timing_rel_tol_factor, jitter_effective_s)
            if abs(frame_duration_s - expected_frame_duration_s) > frame_tolerance_s:
                details = {
                    'measured_s': frame_duration_s, 'expected_s': expected_frame_duration_s,
                    'tolerance_s': frame_tolerance_s,
                    'reason': 'Too long' if frame_duration_s > expected_frame_duration_s else 'Too short', 'dlc': dlc
                }
                log_physical_error('frame_duration_error', frame_duration_s, details)
        except ValueError:
            pass

    if match_dict.get('sof') and match_dict.get('eoh'):
        try:
            sof = float(match_dict['sof'])
            eoh = float(match_dict['eoh'])
            header_duration_s = eoh - sof
            if 0 < header_duration_s < 0.1:
                metrics = physical_metrics['header_duration_values']
                metrics['min'] = min(metrics['min'], header_duration_s)
                metrics['max'] = max(metrics['max'], header_duration_s)
                metrics['sum'] += header_duration_s
                metrics['count'] += 1
        except (ValueError, TypeError):
            pass

    if match_dict.get('eob'):
        try:
            eob_times = [float(t) for t in match_dict['eob'].split() if t.strip()]
            if len(eob_times) > 1:
                expected_byte_duration_s = 10 * bit_duration_s
                byte_tolerance_s = max(expected_byte_duration_s * timing_rel_tol_factor, jitter_effective_s)
                byte_intervals = [eob_times[i+1] - eob_times[i] for i in range(len(eob_times)-1)]
                for interval in byte_intervals:
                    if abs(interval - expected_byte_duration_s) > byte_tolerance_s:
                        details = {
                            'measured_interval_s': interval, 'expected_interval_s': expected_byte_duration_s,
                            'tolerance_s': byte_tolerance_s,
                            'reason': 'Too long' if interval > expected_byte_duration_s else 'Too short'
                        }
                        log_physical_error('byte_timing_error', interval, details)
        except ValueError:
            pass
            
    last_frame_info = log_stats.setdefault('last_frame_info', {'last_eof': None})
    if match_dict.get('sof') and last_frame_info['last_eof'] is not None:
        try:
            sof = float(match_dict['sof'])
            last_eof = last_frame_info['last_eof']
            ifs_s = sof - last_eof
            min_ifs_s = ifs_min_bits * bit_duration_s
            if ifs_s < min_ifs_s:
                details = {'measured_s': ifs_s, 'expected_min_s': min_ifs_s}
                log_physical_error('ifs_error_too_short', ifs_s, details)
        except ValueError:
            pass
    if match_dict.get('eof'):
        try:
            last_frame_info['last_eof'] = float(match_dict['eof'])
        except ValueError:
            pass

    for sync_key_raw in ['hso', 'rso']:
        sync_value_ns_str = match_dict.get(sync_key_raw)
        if sync_value_ns_str:
            try:
                sync_value_ns = float(sync_value_ns_str)
                sync_value_s = sync_value_ns / 1_000_000_000.0
                metric_key_for_values = f'{sync_key_raw}_values_s'
                physical_metrics.setdefault(metric_key_for_values, {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0})
                current_metric_stats = physical_metrics[metric_key_for_values]
                current_metric_stats['min'] = min(current_metric_stats['min'], sync_value_s)
                current_metric_stats['max'] = max(current_metric_stats['max'], sync_value_s)
                current_metric_stats['sum'] += sync_value_s
                current_metric_stats['count'] += 1
            except ValueError:
                pass
def _write_slave_reliability_section(write_html, log_stats):
    reliability_stats = log_stats.get('slave_reliability')
    if not reliability_stats:
        return
    write_html("<details close><summary>Reliability of Slave Responses to Master Headers</summary>")
    write_html("<table><thead><tr><th>Slave Node</th><th>Frame Name</th><th>Requests (Headers Sent)</th><th>Responses (Frames Rx)</th><th>Success Rate</th></tr></thead><tbody>")
    
    for slave_node, frames in sorted(reliability_stats.items()):
        for frame_name, stats in sorted(frames.items()):
            requests = stats.get('requests', 0)
            responses = stats.get('responses', 0)
            if requests == 0:
                continue
            
            rate = (responses / requests) * 100
            rate_status = "OK"
            if rate < 100: rate_status = "WARN"
            if rate < 95: rate_status = "KO"
            
            rate_tag = tag(rate_status, f"{rate:.2f}%")
            
            write_html(f"<tr>"
                       f"<td><code>{escape(slave_node)}</code></td>"
                       f"<td><code>{escape(frame_name)}</code></td>"
                       f"<td>{requests}</td>"
                       f"<td>{responses}</td>"
                       f"<td>{rate_tag}</td>"
                       f"</tr>")
    write_html("</tbody></table></details>")

def _write_schedule_jitter_section(write_html, log_stats, ldf_data):
    slot_timing_stats = log_stats.get('schedule_slot_timing')
    if not slot_timing_stats:
        return     
    import math
    grouped_by_sched = defaultdict(list)
    for (sched_name, slot_idx), stats in slot_timing_stats.items():
        grouped_by_sched[sched_name].append((slot_idx, stats))
    write_html("<details close><summary>Schedule Slot Jitter Analysis</summary>")
    for sched_name, slots in sorted(grouped_by_sched.items()):
        write_html(f"<details close><summary>Table: {escape(sched_name)}</summary>")
        write_html("<table><thead><tr><th>Slot Index</th><th>Frame Name</th><th>Expected Delay (ms)</th><th>Avg. Delay (ms)</th><th>Min (ms)</th><th>Max (ms)</th><th>Jitter (StdDev)</th></tr></thead><tbody>")
        for slot_idx, stats in sorted(slots, key=lambda x: x[0]):
            count = stats['count']
            if count == 0: continue
            frame_name = ldf_data.schedules[sched_name][slot_idx]['frame_name']
            expected_ms = ldf_data.schedules[sched_name][slot_idx]['delay_ms']
            avg_ms = stats['sum_ms'] / count
            min_ms = stats['min_ms']
            max_ms = stats['max_ms']
            var_ms = (stats['sum_sq_ms'] / count) - (avg_ms ** 2)
            stddev_ms = math.sqrt(var_ms) if var_ms > 0 else 0.0
            jitter_threshold_ms = expected_ms * 0.1 
            status = "OK"
            if stddev_ms > jitter_threshold_ms: status = "WARN"
            if stddev_ms > jitter_threshold_ms * 2: status = "KO"
            jitter_tag = tag(status, f"{stddev_ms:.3f}")
            write_html(f"<tr>"
                       f"<td>{slot_idx}</td>"
                       f"<td><code>{escape(frame_name)}</code></td>"
                       f"<td>{expected_ms:.3f}</td>"
                       f"<td>{avg_ms:.3f}</td>"
                       f"<td>{min_ms:.3f}</td>"
                       f"<td>{max_ms:.3f}</td>"
                       f"<td>{jitter_tag}</td>"
                       f"</tr>")
        write_html("</tbody></table>")
        write_html("</details>")
    write_html("</details>")
def _write_physical_errors(write_html, log_stats):
    phys_err = log_stats.get('physical_errors', {})
    ldf_data = log_stats.get('ldf_data_for_report') 
    if not any(details['count'] > 0 for error_type in phys_err.values() for details in error_type.values()):
        return

    write_html("<details close><summary>LIN Physical Layer Errors</summary>")
    
    sorted_error_types = sorted(phys_err.keys(), key=lambda x: PHYSICAL_ERROR_LABELS.get(x, x))
    for err_type in sorted_error_types:
        errors_of_type = phys_err.get(err_type, {})
        if not any(d['count'] > 0 for d in errors_of_type.values()):
            continue
            
        label = PHYSICAL_ERROR_LABELS.get(err_type, err_type)
        write_html(f"<h4>{escape(label)}</h4>")
        write_html("<table><thead><tr><th>Frame ID</th><th>Frame Name</th><th>Occurrences</th><th>Measured</th><th>Expected / Tolerance</th><th>First Timestamp (s)</th></tr></thead><tbody>")
        
        sorted_errors = sorted(errors_of_type.items(), key=lambda item: item[1]['count'], reverse=True)
        
        for (frame_id, value_key), details in sorted_errors:
            if details['count'] == 0: continue
            
            frame_name = "N/A"
            if frame_id != -1 and ldf_data:
                frame_name = next((f.name for f in ldf_data.frames.values() if f.id == frame_id), f"Unknown ID 0x{frame_id:X}")

            example_details = details.get('example_details', {})
            observed_str = "N/A"
            expected_str = "N/A"
            if err_type == 'baudrate_deviation':
                observed_str = f"{example_details.get('value', 0):.2f} bps"
                expected_str = f"{log_stats['config_used'].get('lin_baudrate', 0):.0f} bps ± {log_stats['config_used'].get('physical_baudrate_tolerance_perc', 0):.1f}%"
            elif err_type in ('break_field_error_too_short', 'break_field_error_too_long'):
                measured_us = example_details.get('measured_us')
                expected_min_us = example_details.get('expected_min_us')
                expected_max_us = example_details.get('expected_max_us')
                if all(v is not None for v in [measured_us, expected_min_us, expected_max_us]):
                    observed_str = f"{measured_us:.3f} μs"
                    expected_str = f"{expected_min_us:.3f} - {expected_max_us:.3f} μs"
            elif err_type == 'ifs_error_too_short':
                measured_s = example_details.get('measured_s')
                expected_s = example_details.get('expected_min_s')
                if all(v is not None for v in [measured_s, expected_s]):
                    observed_str = f"{measured_s * 1e6:.1f} μs"
                    expected_str = f"≥ {expected_s * 1e6:.1f} μs"
            
            write_html(
                f"<tr>"
                f"<td><code>0x{frame_id:X}</code></td>"
                f"<td><code>{escape(frame_name)}</code></td>"
                f"<td>{details['count']}</td>"
                f"<td><code>{observed_str}</code></td>"
                f"<td><code>{expected_str}</code></td>"
                f"<td>{details.get('first_ts', 0):.6f}</td>"
                f"</tr>"
            )
        write_html("</tbody></table>")
    write_html("</details>")
def update_slave_response_stats(
    entry: LogEntry, ldf_data: LDFData,
    ldf_id_to_frame_map: Dict[int, LDFFrame], log_stats: Dict[str, Any]
):
    if entry.channel != 'LIN' or entry.type != 'Rx' or not entry.physical_metadata:
        return
    frame_def = ldf_id_to_frame_map.get(entry.frame_id_int)
    master_node = ldf_data.nodes.get('master')
    if not frame_def or not frame_def.publisher or not master_node or frame_def.publisher == master_node:
        return
    log_stats['node_response_stats'][frame_def.publisher]['frames_published'] += 1
    eoh_str = entry.physical_metadata.get('eoh')
    eob_str = entry.physical_metadata.get('eob')
    if not eoh_str or not eob_str:
        return
    try:
        eoh_ts = float(eoh_str)
        first_eob_ts = float(eob_str.strip().split()[0])
        response_time_s = first_eob_ts - eoh_ts
        if 0 < response_time_s < 0.01:
            stats = log_stats['node_response_stats'][frame_def.publisher]
            stats['min_s'] = min(stats['min_s'], response_time_s)
            stats['max_s'] = max(stats['max_s'], response_time_s)
            stats['sum_s'] += response_time_s
            stats['count'] += 1
    except (ValueError, TypeError, IndexError):
        pass
def initialize_log_stats(config: Dict[str, Any]) -> Dict[str, Any]:
    baudrate = config.get('lin_baudrate', DEFAULT_LIN_BAUDRATE)
    def frame_stats_factory():
        return {'count': 0, 'delta_count': 0, 'sum_delta': 0.0, 'min_delta': float('inf'), 'max_delta': 0.0, 'last_ts': None, 'frame_name': None, 'last_was_active': False}
    
    def slot_timing_factory():
        return {'sum_ms': 0.0, 'sum_sq_ms': 0.0, 'count': 0, 'min_ms': float('inf'), 'max_ms': float('-inf')}
    def timing_mismatch_factory():
        return {
            'count': 0, 'sum_observed_ms': 0.0, 'min_observed_ms': float('inf'), 'max_observed_ms': float('-inf'),
            'expected_ms': 0.0, 'frame_name': '', 'publisher': '', 'first_ts': None, 'last_ts': None
        }
    stats = {
        'error_summary': {
            'dlc': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None, 'example_line': None, 'frame_name': None}),
            'checksum': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None, 'example_line': None, 'frame_name': None}),
            'transmission': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None, 'example_line': None, 'affected_id_str': None}),
            'sync': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None, 'example_details': None}),
            'inactivity': {'periods': 0, 'total_duration': 0.0, 'max_duration': 0.0, 'first_start': None, 'last_end': None},
            'frames_after_sleep': defaultdict(lambda: {'count': 0, 'first_ts': None, 'example_line': None}),
            'parity': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None, 'example_line': None})
        },
        'foreign_ids_summary': {'lin': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None}), 'can': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None})},
        'network_cycle_summary': {'total_cycles_detected': 0, 'cycles_completed': 0, 'cycles_incomplete': 0, 'cycles_no_master_response': 0, 'cycles_with_frames_after_sleep': 0, 'first_cycle_start_ts': None, 'last_cycle_end_ts': None, 'example_problem_cycle': None, 'master_response_delays_ms_stats': {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0}},
        'schedule_analysis': {'cycles': [], 'global_errors': []},
        'logger_cycle_state': {'active': False, 'start_ts': None},
        'logger_activity_periods': [],
        'schedule_timing_mismatches': defaultdict(timing_mismatch_factory),
        'schedule_runtime_state': {'active_schedules': [], 'current_index': 0, 'last_event_timestamp': None, 'cycle_start_timestamp': None, 'cycle_log': [], 'cycle_id': 0, 'has_timing_errors': False},
        'schedule_slot_timing': defaultdict(slot_timing_factory),
        'slave_reliability': defaultdict(lambda: defaultdict(lambda: {'requests': 0, 'responses': 0})),
        'node_response_stats': defaultdict(lambda: {'min_s': float('inf'), 'max_s': 0.0, 'sum_s': 0.0, 'count': 0, 'frames_published': 0}),
        'signal_stats': defaultdict(lambda: {'min_phys': float('inf'), 'max_phys': float('-inf'), 'min_display': None, 'max_display': None, 'unit': '', 'encoding_type': 'physical', 'first_ts': None, 'last_ts': None, 'count': 0, 'network_type':None}),
        'frame_timing_stats': defaultdict(lambda: defaultdict(frame_stats_factory)),
        'physical_errors': {pe_key: defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None, 'example_details': None}) for pe_key in PHYSICAL_ERROR_LABELS.keys()},
        'physical_metrics': {
            'baudrate_values': {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0},
            'header_duration_values': {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0},
            'frame_duration_values': {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0},
            'hso_values_s': {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0},
            'rso_values_s': {'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0},
        },
        'gateway_results': defaultdict(lambda: {
            'comparisons': 0, 'matches': 0, 'mismatches_value': 0, 'mismatches_type': 0, 'mismatches_timing': 0,
            'first_ts': None, 'last_ts': None,
            'mismatch_examples': [],
            'mapping_info': None,
            'latency_stats': {'sum': 0.0, 'min': float('inf'), 'max': float('-inf'), 'count': 0, 'average': None},
            'latency_examples': []
        }),
        'slave_faults': defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None, 'node_name': None}),
        'network_cycle_state': {'active': False, 'start_time': None, 'first_master_time': None, 'first_master_found': False, 'slaves_responded_in_cycle': set(), 'current_cycle_start_line': None, 'current_cycle_end_line': None, 'current_cycle_details': {}, 'just_slept': False, 'saw_first_event': False, 'last_wake_event_ts': None},
        'node_timing_stats': defaultdict(lambda: {'wake_up_time': {'count': 0, 'sum': 0.0, 'min': float('inf'), 'max': 0.0, 'first_ts': None, 'last_ts': None}, 'response_time': {'count': 0, 'sum': 0.0, 'min': float('inf'), 'max': 0.0, 'first_ts': None, 'last_ts': None}, 'bus_load_s': 0.0, 'seen_since_wake': False, 'first_frame_ts_in_cycle': None}),
        'gateway_pending_sources': defaultdict(lambda: defaultdict(collections.deque)),
        'last_lin_activity_ts': None, 'last_global_ts': None,
        'log_info': {'start_time': None, 'end_time': None, 'duration': 0.0, 'total_entries_processed': 0, 'lin_entries': 0, 'can_entries': 0, 'rx_count': 0, 'tx_count': 0},
        'lin_bus_load': {
            'total_busy_time_s': 0.0,
            'baudrate': baudrate,
            'percentage': 0.0,
            'bus_load_by_window': [],
            'duration_analyzed_s': 0.0,
            'average_percentage': 0.0,
            'max_percentage': 0.0,
        },
        'signal_to_frame_map': {}, '_internal_parse_stats': {'processed': 0, 'skipped': 0},
        'config_used': config.copy()
    }
    stats['can_activity_stats'] = defaultdict(lambda: {'first_ts': None, 'last_ts': None, 'frame_count': 0})
    return stats
def _write_schedule_adherence_section(write_html, log_stats, ldf_data):
    analysis = log_stats.get('schedule_analysis', {})
    cycles = analysis.get('cycles', [])
    global_errors = analysis.get('global_errors', [])
    timing_mismatches = log_stats.get('schedule_timing_mismatches', {})
    if not cycles and not global_errors and not timing_mismatches:
        return
    write_html("<h2>Schedule Adherence Analysis</h2>")
    summary = defaultdict(lambda: {'detected': 0, 'completed': 0, 'aborted': 0, 'error_free_completed': 0})
    for cycle in cycles:
        sched_name = cycle['schedule_name']
        if sched_name in ("Unknown", "Ambiguous"): continue
        has_sequence_errors = any(e['type'] not in ('Cycle Start', 'Cycle Completed') for e in cycle['events'])
        has_errors = has_sequence_errors or cycle.get('had_timing_errors', False)
        summary[sched_name]['detected'] += 1
        if cycle['status'] == 'Completed':
            summary[sched_name]['completed'] += 1
            if not has_errors: summary[sched_name]['error_free_completed'] += 1
        else:
            summary[sched_name]['aborted'] += 1
    if summary:
        write_html("<details close><summary>Schedule Performance Summary</summary>")
        write_html("<table><thead><tr><th>Schedule Name</th><th>Cycles Detected</th><th>Cycles Completed</th><th>Cycles Aborted</th><th>Error-Free Cycles</th></tr></thead><tbody>")
        for name, data in sorted(summary.items()):
            health_percent = (data['error_free_completed'] / data['completed'] * 100) if data['completed'] > 0 else 0
            health_tag = tag('OK' if health_percent >= 99.9 else ('WARN' if health_percent > 95 else 'KO'), f"{health_percent:.1f}%")
            if data['completed'] == 0: health_tag = tag('NA', 'N/A')
            aborted_tag = tag('KO' if data['aborted'] > 0 else 'OK', data['aborted'])
            write_html(f"<tr><td><code>{escape(name)}</code></td><td>{data['detected']}</td><td>{data['completed']}</td><td>{aborted_tag}</td><td>{health_tag} ({data['error_free_completed']}/{data['completed']})</td></tr>")
        write_html("</tbody></table></details>")
    all_frames_by_name = {f.name: f for f in ldf_data.frames.values()}
    if timing_mismatches:
        write_html("<details close><summary>Timing Mismatch</summary>")
        write_html("<table><thead><tr><th>Schedule</th><th>Slot</th><th>Frame</th><th>Publisher</th><th>Occurrences</th><th>Expected (ms)</th><th>Observed (Min/Avg/Max ms)</th></tr></thead><tbody>")
        sorted_mismatches = sorted(timing_mismatches.items(), key=lambda item: (item[0][0], item[0][1]))
        for (sched_name, slot_idx), stats in sorted_mismatches:
            if stats['count'] == 0: continue
            avg_ms = stats['sum_observed_ms'] / stats['count']
            observed_str = f"{stats['min_observed_ms']:.2f} / <b>{avg_ms:.2f}</b> / {stats['max_observed_ms']:.2f}"
            write_html(f"<tr>"
                       f"<td><code>{escape(sched_name)}</code></td>"
                       f"<td>{slot_idx}</td>"
                       f"<td><code>{escape(stats['frame_name'])}</code></td>"
                       f"<td><code>{escape(stats['publisher'])}</code></td>"
                       f"<td>{stats['count']}</td>"
                       f"<td>{stats['expected_ms']:.2f}</td>"
                       f"<td>{observed_str}</td>"
                       f"</tr>")
        write_html("</tbody></table></details>")
    failures_by_type = defaultdict(list)
    for cycle in cycles:
        for event in cycle['events']:
            if event['type'] not in ('Cycle Start', 'Cycle Completed', 'Timing Mismatch'):
                details = event['details'].copy()
                details['cycle_id'] = cycle['id']
                details['ts'] = event['ts']
                failures_by_type[event['type']].append(details)
    for g_error in global_errors:
        details = g_error['details'].copy(); details['ts'] = g_error['ts']; details['cycle_id'] = 'N/A'
        failures_by_type[g_error['type']].append(details)
    failure_order = ['Sequence Mismatch', 'Intrusion Frame']
    for f_type in failure_order:
        if f_type not in failures_by_type: continue
        events = failures_by_type[f_type]
        write_html(f"<details close><summary>{f_type.replace('_', ' ')}</summary>")
        if f_type == 'Sequence Mismatch':
            write_html("<table><thead><tr><th>Cycle #</th><th>Timestamp (s)</th><th>Observed Frame</th><th>Publisher Node</th><th>Expected Frame(s)</th></tr></thead><tbody>")
            for event in sorted(events, key=lambda x: x['ts']):
                frame_name = event.get('observed', '-')
                node_name = all_frames_by_name.get(str(frame_name), LDFFrame(name='-', publisher='-')).publisher
                expected_str = ", ".join(f"<code>{escape(f)}</code>" for f in event.get('expected', []))
                write_html(f"<tr><td>#{event['cycle_id']}</td><td>{event['ts']:.6f}</td><td><code>{escape(str(frame_name))}</code></td><td><code>{escape(str(node_name))}</code></td><td>{expected_str}</td></tr>")
        elif f_type == 'Intrusion Frame':
            write_html("<table><thead><tr><th>Timestamp (s)</th><th>Frame</th><th>Publisher Node</th></tr></thead><tbody>")
            for event in sorted(events, key=lambda x: x['ts']):
                frame_name = event.get('frame_name', '-')
                node_name = all_frames_by_name.get(str(frame_name), LDFFrame(name='-', publisher='-')).publisher
                write_html(f"<tr><td>{event['ts']:.6f}</td><td><code>{escape(str(frame_name))}</code></td><td><code>{escape(str(node_name))}</code></td></tr>")
        write_html("</tbody></table></details>")
def validate_transmission_errors(
    entry: LogEntry,
    log_stats: Dict[str, Any]
) -> None:
    error_type = None
    if entry.type == 'Spike':
        error_type = 'Spike'
    elif entry.type == 'TransmErr':
        error_type = 'TransmErr'
    elif entry.type == 'RcvError':
        error_type = 'RcvError'
    if error_type:
        frame_id_key = entry.frame_id_int if entry.frame_id_int != -1 else None
        error_key = (error_type, frame_id_key)
        summary = log_stats['error_summary']['transmission'][error_key]
        summary['count'] += 1
        if summary['first_ts'] is None:
            summary['first_ts'] = entry.timestamp
            summary['example_line'] = entry.raw_line
            summary['affected_id_str'] = entry.frame_id
        summary['last_ts'] = entry.timestamp
def _write_logger_activity_section(write_html, log_stats):
    logger_periods = log_stats.get('logger_activity_periods')
    if not logger_periods:
        return
    write_html("<details close><summary>Logger Activity Periods</summary>")
    write_html("<table><thead><tr><th>#</th><th>Start Timestamp (s)</th><th>End Timestamp (s)</th><th>Duration (s)</th></tr></thead><tbody>")
    for i, period in enumerate(logger_periods, 1):
        write_html(f"<tr>"
                   f"<td>{i}</td>"
                   f"<td>{period['start_ts']:.6f}</td>"
                   f"<td>{period['end_ts']:.6f}</td>"
                   f"<td>{period['duration_s']:.3f}</td>"
                   f"</tr>")
    write_html("</tbody></table></details>")
def update_network_cycle_state(entry: LogEntry, ldf_data: LDFData, ldf_id_to_frame_map: Dict[int, LDFFrame], log_stats: Dict[str, Any]):
    summary = log_stats['network_cycle_summary']
    state = log_stats['network_cycle_state']
    event_channel = getattr(entry, 'event_channel', -1)
    is_sleep_mode_event = entry.type == 'SleepModeEvent'
    raw_line_lower = entry.raw_line.lower()
    is_bus_wake_event = is_sleep_mode_event and event_channel == 1 and ('waking up' in raw_line_lower or 'wake up' in raw_line_lower)
    is_bus_sleep_command = entry.frame_id_int == 0x3C and entry.data and entry.data[0] == 0x00
    is_any_sleep_event = (is_sleep_mode_event and 'entering sleep mode' in raw_line_lower) or is_bus_sleep_command
    if not state['active']:
        if is_bus_wake_event:
            state['active'] = True
            state['last_wake_event_ts'] = entry.timestamp
            state['first_master_found'] = False
            summary['total_cycles_detected'] += 1
            if summary['first_cycle_start_ts'] is None:
                summary['first_cycle_start_ts'] = entry.timestamp
            state['current_cycle_details'] = {'start': entry.timestamp, 'start_line': entry.raw_line, 'end': None, 'end_line': None, 'problem_flags': set()}
            log_stats.setdefault('active_schedules', set()).update(ldf_data.schedules.keys())
        elif not is_any_sleep_event and entry.channel == 'LIN' and entry.type in ('Rx', 'Tx', 'TransmErr', 'RcvError'):
            state['active'] = True
            state['last_wake_event_ts'] = None
            state['first_master_found'] = False
            summary['total_cycles_detected'] += 1
            if summary['first_cycle_start_ts'] is None:
                summary['first_cycle_start_ts'] = entry.timestamp
            state['current_cycle_details'] = {'start': entry.timestamp, 'start_line': f"Implicit cycle start on first LIN frame: {entry.raw_line.strip()}", 'end': None, 'end_line': None, 'problem_flags': {'Implicit Start'}}
            log_stats.setdefault('active_schedules', set()).update(ldf_data.schedules.keys())
    
    if state['active']:
        if is_any_sleep_event:
            state['active'] = False
            summary['last_cycle_end_ts'] = entry.timestamp
            cycle_details = state.get('current_cycle_details', {})
            cycle_details['end'] = entry.timestamp
            cycle_details['end_line'] = entry.raw_line
            if not state.get('first_master_found', False):
                summary['cycles_no_master_response'] += 1
                cycle_details.setdefault('problem_flags', set()).add('No Master Response')
            summary['cycles_completed'] += 1
            if bool(cycle_details.get('problem_flags')) and summary['example_problem_cycle'] is None:
                summary['example_problem_cycle'] = cycle_details.copy()
            state['current_cycle_details'] = {}
            state['last_wake_event_ts'] = None
            state['first_master_found'] = False
        elif not state.get('first_master_found', False):
            if entry.channel == 'LIN' and entry.type.lower() == 'rx':
                frame = ldf_id_to_frame_map.get(entry.frame_id_int)
                master_node_name = ldf_data.nodes.get('master')
                if frame and master_node_name and frame.publisher and frame.publisher.strip() == master_node_name:
                    state['first_master_found'] = True
                    if state.get('last_wake_event_ts') is not None:
                        delay = entry.timestamp - state['last_wake_event_ts']
                        if 'current_cycle_details' in state:
                            state['current_cycle_details']['first_master_delay_ms'] = delay * 1000
                        delay_stats = summary.setdefault('master_response_delays_ms_stats',{'min': float('inf'), 'max': float('-inf'), 'sum': 0.0, 'count': 0})
                        delay_ms_val = delay * 1000
                        delay_stats['min'] = min(delay_stats['min'], delay_ms_val)
                        delay_stats['max'] = max(delay_stats['max'], delay_ms_val)
                        delay_stats['sum'] += delay_ms_val
                        delay_stats['count'] += 1
                        state['last_wake_event_ts'] = None
    if is_sleep_mode_event and event_channel == 0:
        logger_state = log_stats['logger_cycle_state']
        is_logger_start = 'starting up' in raw_line_lower or 'waking up' in raw_line_lower
        is_logger_sleep = 'entering sleep mode' in raw_line_lower
        if not logger_state['active'] and is_logger_start:
            logger_state['active'] = True
            logger_state['start_ts'] = entry.timestamp
        elif logger_state['active'] and is_logger_sleep:
            start_ts = logger_state.get('start_ts')
            if start_ts is not None:
                log_stats['logger_activity_periods'].append({
                    'start_ts': start_ts,
                    'end_ts': entry.timestamp,
                    'duration_s': entry.timestamp - start_ts
                })
            logger_state['active'] = False
            logger_state['start_ts'] = None
def calculate_checksum(data_bytes: List[int], pid_for_enhanced: Optional[int] = None) -> int:
    """
    Calcula o checksum LIN de acordo com a especificação LIN 2.x.
    
    LIN suporta dois tipos de checksum:
    
    1. Classic Checksum (LIN 1.x):
       - Calcula apenas sobre os bytes de dados
       - Sum = D0 + D1 + ... + Dn
       - Checksum = 0xFF - (Sum % 256)
    
    2. Enhanced Checksum (LIN 2.x) - RECOMENDADO:
       - Inclui o Protected ID no cálculo
       - Sum = PID + D0 + D1 + ... + Dn
       - Checksum = 0xFF - (Sum % 256)
       - Proporciona maior integridade de dados
    
    Args:
        frame_id (int): ID do frame (0-63)
        data (List[int]): Bytes de dados (sem o checksum)
        checksum_type (str): 'classic' ou 'enhanced'
    
    Returns:
        int: Valor do checksum (0-255)
    
    Nota:
        O Protected ID (PID) é calculado com bits de paridade P0 e P1:
        PID = ID5 ID4 ID3 ID2 ID1 ID0 P1 P0
    """
    valid_data = [d for d in data_bytes if isinstance(d, int)]
    if pid_for_enhanced is not None:
        if not (0 <= pid_for_enhanced <= 0xFF):
             raise ValueError(f"Invalid PID {pid_for_enhanced} for enhanced checksum calculation.")
        sum_val = pid_for_enhanced + sum(valid_data)
    else:
        if not valid_data:
            return 0xFF
        sum_val = sum(valid_data)
    while sum_val > 0xFF:
        sum_val = (sum_val & 0xFF) + (sum_val >> 8)
    checksum = (~sum_val) & 0xFF
    return checksum
def parse_dbc_single_file(dbc_path: str) -> Tuple[Dict[int, DBCMessage], Dict[str, Any]]:
    """
    Faz parsing de um arquivo DBC (CAN Database).
    
    O arquivo DBC é o formato padrão da indústria automotiva para definir
    redes CAN, incluindo mensagens, sinais, scaling e atributos.
    
    Args:
        dbc_path (str): Caminho para o arquivo .dbc
    
    Returns:
        Tuple contendo:
        - List[DBCMessage]: Lista de mensagens CAN definidas
        - Dict: Dicionário com atributos e configurações adicionais
    
    Formato DBC:
        BO_ msg_id msg_name: dlc sender
        SG_ signal_name : start_bit|length@byte_order sign (factor,offset) [min|max] "unit" receiver
    """
    messages: Dict[int, DBCMessage] = {}
    global_attributes_this_file: Dict[str, Any] = {}
    current_msg_obj: Optional[DBCMessage] = None
    EXTENDED_ID_FLAG_BIT31 = 0x80000000
    STANDARD_ID_MAX = 0x7FF
    EXTENDED_ID_MASK_29BIT = 0x1FFFFFFF
    try:
        with open(dbc_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line_content in enumerate(f, 1):
                line = line_content.strip()
                if not line or line.startswith(('VERSION', 'BU_', 'CM_', 'BS_')):
                    continue
                ba_def_def_match = DBC_BA_DEF_DEF_RE.match(line)
                if ba_def_def_match:
                    attr_name_raw, attr_value_str = ba_def_def_match.groups()
                    attr_name = attr_name_raw.strip('"')
                    if attr_name == "Baudrate":
                        if "Baudrate" not in global_attributes_this_file or \
                           global_attributes_this_file.get("_Baudrate_source") == "default":
                            try:
                                baud_val = int(attr_value_str.strip().strip('"'))
                                global_attributes_this_file["Baudrate"] = baud_val
                                global_attributes_this_file["_Baudrate_source"] = "default"
                            except ValueError:
                                pass
                    continue
                ba_global_match = DBC_BA_NON_OBJECT_SPECIFIC_RE.match(line)
                if ba_global_match:
                    attr_name_raw, attr_value_str = ba_global_match.groups()
                    attr_name = attr_name_raw.strip('"')
                    if attr_name == "Baudrate":
                        try:
                            baud_val = int(attr_value_str.strip().strip('"'))
                            global_attributes_this_file["Baudrate"] = baud_val
                            global_attributes_this_file["_Baudrate_source"] = "explicit"
                        except ValueError:
                            pass
                    continue
                msg_match = MSG_DEF_RE.match(line)
                if msg_match:
                    msg_id_str, msg_name, dlc_str, node_name_sender = msg_match.groups()
                    try:
                        dbc_raw_id = int(msg_id_str)
                        parsed_dlc = int(dlc_str)
                        is_extended_frame_dbc = False
                        actual_can_id = dbc_raw_id
                        if dbc_raw_id & EXTENDED_ID_FLAG_BIT31:
                            is_extended_frame_dbc = True
                            actual_can_id = dbc_raw_id & EXTENDED_ID_MASK_29BIT
                        elif dbc_raw_id > STANDARD_ID_MAX:
                            is_extended_frame_dbc = True
                            actual_can_id = dbc_raw_id & EXTENDED_ID_MASK_29BIT
                        else:
                            if dbc_raw_id > STANDARD_ID_MAX:
                                is_extended_frame_dbc = True
                                actual_can_id = dbc_raw_id & EXTENDED_ID_MASK_29BIT
                            else:
                                is_extended_frame_dbc = False
                                actual_can_id = dbc_raw_id
                        new_message = DBCMessage(
                            name=msg_name,
                            id=actual_can_id,
                            signals=[],
                            dlc=parsed_dlc,
                            node_name=node_name_sender
                        )
                        new_message.attributes['_is_extended_format_dbc_'] = is_extended_frame_dbc
                        new_message.attributes['_dbc_raw_id_'] = dbc_raw_id
                        messages[actual_can_id] = new_message
                        current_msg_obj = new_message
                    except ValueError:
                        current_msg_obj = None
                    continue
                if line.startswith('SG_') and current_msg_obj:
                    sig_match = DBC_SIG_RE.match(line)
                    if not sig_match:
                        sig_match = DBC_SIG_RE_SIMPLE.match(line)
                    if sig_match:
                        groups = list(sig_match.groups())
                        expected_groups_full = 12
                        expected_groups_simple = 9
                        if len(groups) < expected_groups_full and len(groups) == expected_groups_simple:
                            if len(groups) == expected_groups_simple:
                                temp_groups = groups[:8]
                                temp_groups.extend([None, None])
                                temp_groups.append(groups[8])
                                temp_groups.append(None)
                                groups = temp_groups
                        elif len(groups) < expected_groups_full:
                             while len(groups) < expected_groups_full:
                                 groups.append(None)
                        (sig_name, multiplexer_indicator, start_bit_str, length_str, byte_order_char,
                         sign_char, factor_str, offset_str,
                         min_val_str, max_val_str, unit, receivers_str) = groups[:expected_groups_full]
                        try:
                            start_bit = int(start_bit_str)
                            length = int(length_str)
                            factor = float(factor_str)
                            offset = float(offset_str)
                            is_big_endian = (byte_order_char == '0')
                            is_signed = (sign_char == '-')
                            min_defined = float(min_val_str) if min_val_str and min_val_str.strip() else None
                            max_defined = float(max_val_str) if max_val_str and max_val_str.strip() else None
                            is_mux_switch = False
                            mux_val = None
                            if multiplexer_indicator:
                                indicator_lower = multiplexer_indicator.lower()
                                if indicator_lower == 'm':
                                    is_mux_switch = True
                                elif indicator_lower.startswith('m') and len(indicator_lower) > 1:
                                    try:
                                        mux_val = int(indicator_lower[1:])
                                    except ValueError:
                                        pass
                            new_signal = DBCSignal(
                                name=sig_name, start_bit=start_bit, length=length,
                                factor=factor, offset=offset, unit=(unit.strip() if unit else ""),
                                is_big_endian=is_big_endian, is_signed=is_signed,
                                logical_map={}, is_multiplexer_switch=is_mux_switch,
                                multiplexer_value=mux_val
                            )
                            setattr(new_signal, 'min_value_defined', min_defined)
                            setattr(new_signal, 'max_value_defined', max_defined)
                            current_msg_obj.signals.append(new_signal)
                        except (ValueError, TypeError) as e:
                            pass
                    continue
                ba_bo_match = re.match(r'BA_\s+"([^"]+)"\s+BO_\s+(\d+)\s+([^;]+);', line)
                if ba_bo_match:
                    attr_name, msg_id_str_ba, attr_val_str = ba_bo_match.groups()
                    try:
                        target_msg_dbc_raw_id = int(msg_id_str_ba)
                        ba_actual_can_id = target_msg_dbc_raw_id
                        if target_msg_dbc_raw_id & EXTENDED_ID_FLAG_BIT31:
                            ba_actual_can_id = target_msg_dbc_raw_id & EXTENDED_ID_MASK_29BIT
                        else:
                            if target_msg_dbc_raw_id > STANDARD_ID_MAX:
                                ba_actual_can_id = target_msg_dbc_raw_id & EXTENDED_ID_MASK_29BIT
                        target_message_for_attr: Optional[DBCMessage] = None
                        if current_msg_obj and current_msg_obj.id == ba_actual_can_id:
                            target_message_for_attr = current_msg_obj
                        elif ba_actual_can_id in messages:
                             target_message_for_attr = messages[ba_actual_can_id]
                        if target_message_for_attr:
                            try:
                                attr_val: Any = int(attr_val_str)
                            except ValueError:
                                try:
                                    attr_val = float(attr_val_str)
                                except ValueError:
                                    attr_val = attr_val_str.strip().strip('"')
                            target_message_for_attr.attributes[attr_name] = attr_val
                    except ValueError:
                        pass
                    continue
            if current_msg_obj:
                messages[current_msg_obj.id] = current_msg_obj
            f.seek(0)
            for line_num_val, line_content_val in enumerate(f, 1):
                line_val = line_content_val.strip()
                if not line_val.startswith('VAL_ '):
                    continue
                val_match = DBC_VAL_RE.match(line_val)
                if val_match:
                    msg_id_str_val, sig_name_val, val_defs_str = val_match.groups()
                    try:
                        val_dbc_raw_id = int(msg_id_str_val)
                        val_actual_can_id = val_dbc_raw_id
                        if val_dbc_raw_id & EXTENDED_ID_FLAG_BIT31:
                            val_actual_can_id = val_dbc_raw_id & EXTENDED_ID_MASK_29BIT
                        else:
                            if val_dbc_raw_id > STANDARD_ID_MAX:
                                val_actual_can_id = val_dbc_raw_id & EXTENDED_ID_MASK_29BIT
                        target_msg = messages.get(val_actual_can_id)
                        if target_msg:
                            target_sig = next((s for s in target_msg.signals if s.name == sig_name_val), None)
                            if target_sig:
                                val_pairs = VAL_PAIR_RE.findall(val_defs_str)
                                for raw_val_str, label in val_pairs:
                                    try:
                                        target_sig.logical_map[int(raw_val_str)] = label.strip().strip('"')
                                    except ValueError: pass
                    except ValueError: pass
    except FileNotFoundError:
        raise
    except Exception as e:
        raise IOError(f"Could not read or parse DBC file: {e}") from e
    return messages, global_attributes_this_file
def find_message_details_for_gateway(
    network_type: str,
    message_name: str,
    signal_name: str,
    ldf_data: Optional[LDFData],
    can_dbcs: Dict[str, Dict[int, DBCMessage]],
    warnings_list: List[Dict[str, Any]],
    map_index_for_context: int,
    role_for_context: str
) -> Optional[Tuple[int, Union[LDFFrame, DBCMessage]]]:
    context = {'map_idx': map_index_for_context, 'role': role_for_context}
    message_name_clean = message_name.strip()
    signal_name_clean = signal_name.strip()
    if network_type == 'LIN':
        if not ldf_data:
            warnings_list.append({
                'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
                'type': 'ldf_missing_data', 'context': context,
                'message': f"LDF data is not available for LIN network."
            })
            return None
        frame_obj = None
        for fname, fobj in ldf_data.frames.items():
            if fname.strip() == message_name_clean:
                frame_obj = fobj
                break
        if frame_obj:
            if any(s.name.strip() == signal_name_clean for s in frame_obj.signals):
                if frame_obj.id is not None:
                    return frame_obj.id, frame_obj
                else:
                    warnings_list.append({
                        'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
                        'type': 'lin_frame_no_id', 'context': context,
                        'message': f"LIN frame '{message_name_clean}' found but has no assignable ID for gateway."
                    })
                    return None
            else:
                warnings_list.append({
                    'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
                    'type': 'signal_not_in_lin_frame', 'context': context,
                    'message': f"Signal '{signal_name_clean}' not found in LIN frame '{message_name_clean}'."
                })
                return None
        else:
            warnings_list.append({
                'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
                'type': 'lin_frame_not_found', 'context': context,
                'message': f"LIN frame '{message_name_clean}' not found in LDF."
            })
            return None
    elif network_type.upper().startswith('CAN'):
        dbc_for_channel = can_dbcs.get(network_type.upper())
        if dbc_for_channel:
            for msg_id_candidate, msg_obj_candidate in dbc_for_channel.items():
                if msg_obj_candidate.name.strip() == message_name_clean:
                    if any(s.name.strip() == signal_name_clean for s in msg_obj_candidate.signals):
                        return msg_id_candidate, msg_obj_candidate
                    else:
                        warnings_list.append({
                            'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
                            'type': 'signal_not_in_can_message', 'context': context,
                            'message': f"Signal '{signal_name_clean}' not found in CAN message '{message_name_clean}' (ID: 0x{msg_id_candidate:X}) on {network_type}."
                        })
                        return None
            warnings_list.append({
                'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
                'type': 'can_message_not_found', 'context': context,
                'message': f"CAN message '{message_name_clean}' not found in DBC for {network_type}."
            })
            return None
        else:
            warnings_list.append({
                'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
                'type': 'dbc_missing_for_channel', 'context': context,
                'message': f"No DBC data found for channel '{network_type}'."
            })
            return None
    else:
        warnings_list.append({
            'signal': signal_name_clean, 'message_name': message_name_clean, 'network': network_type,
            'type': 'unknown_network_type', 'context': context,
            'message': f"Unknown network type '{network_type}' specified in gateway map."
        })
        return None
def parse_dbcs_for_channel(dbc_paths: List[str]) -> Tuple[Dict[int, DBCMessage], Dict[str, Any]]:
    channel_messages_aggregated: Dict[int, AggregatedMessageData] = {}
    global_attributes_aggregated: Dict[str, Any] = {}
    first_baudrate_found = None
    for dbc_path in dbc_paths:
        try:
            current_file_messages, current_file_attributes = parse_dbc_single_file(dbc_path)
            for msg_id, msg_obj in current_file_messages.items():
                if msg_id not in channel_messages_aggregated:
                    channel_messages_aggregated[msg_id] = {
                        'name': msg_obj.name,
                        'id': msg_obj.id,
                        'signals_dict': {s.name: s for s in msg_obj.signals},
                        'dlc': msg_obj.dlc,
                        'node_name': msg_obj.node_name,
                        'attributes': msg_obj.attributes.copy()
                    }
                else:
                    existing_aggregation = channel_messages_aggregated[msg_id]
                    for sig in msg_obj.signals:
                        existing_aggregation['signals_dict'][sig.name] = sig
                    if existing_aggregation.get('dlc') is None and msg_obj.dlc is not None:
                        existing_aggregation['dlc'] = msg_obj.dlc
                    if existing_aggregation.get('node_name') is None and msg_obj.node_name is not None:
                         existing_aggregation['node_name'] = msg_obj.node_name
                    existing_aggregation.setdefault('attributes', {}).update(msg_obj.attributes)
                file_baudrate = current_file_attributes.get("Baudrate")
                if file_baudrate is not None:
                    if first_baudrate_found is None:
                        first_baudrate_found = file_baudrate
                        global_attributes_aggregated["Baudrate"] = file_baudrate
                    elif first_baudrate_found != file_baudrate:
                        print(f"ERROR Linspector (Channel Parse): Baudrate mismatch! Was {first_baudrate_found}, found {file_baudrate} in {dbc_path}")
                        raise ValueError(f"Baudrate mismatch in DBCs for the same channel. Found {first_baudrate_found} and {file_baudrate} in {dbc_path}.")
                else:
                    existing_aggregation = channel_messages_aggregated[msg_id]
                    existing_signals = existing_aggregation['signals_dict']
                    for sig in msg_obj.signals:
                        existing_signals[sig.name] = sig
                    existing_aggregation['name'] = msg_obj.name
                    existing_aggregation['dlc'] = getattr(msg_obj, 'dlc', existing_aggregation['dlc'])
                    existing_aggregation['node_name'] = getattr(msg_obj, 'node_name', existing_aggregation['node_name'])
        except Exception as e:
            print(f"Error parsing DBC file {dbc_path}: {e}")
            continue
    final_channel_messages: Dict[int, DBCMessage] = {}
    for msg_id, agg_data in channel_messages_aggregated.items():
        final_channel_messages[msg_id] = DBCMessage(
            name=agg_data['name'],
            id=agg_data['id'],
            signals=list(agg_data['signals_dict'].values()),
            dlc=agg_data['dlc'],
            node_name=agg_data.get('node_name'),
            attributes=agg_data.get('attributes', {})
        )
    return final_channel_messages, global_attributes_aggregated
def validate_lin_ids_and_dlcs(
    entry: LogEntry,
    ldf_id_to_frame_map: Dict[int, LDFFrame],
    log_stats: Dict[str, Any]
) -> None:
    if entry.channel != 'LIN' or entry.type.lower() != 'rx':
        return
    frame_definition = ldf_id_to_frame_map.get(entry.frame_id_int)
    critical_frames = {0x3C, 0x3D}
    if not frame_definition:
        foreign_id_key = entry.frame_id
        summary = log_stats['foreign_ids_summary']['lin'][foreign_id_key]
        summary['count'] += 1
        if summary['first_ts'] is None:
            summary['first_ts'] = entry.timestamp
        summary['last_ts'] = entry.timestamp
    elif entry.data is not None:
        expected_dlc = frame_definition.dlc
        observed_dlc = len(entry.data)
        if observed_dlc != expected_dlc:
            error_key = (entry.frame_id_int, expected_dlc, observed_dlc)
            summary = log_stats['error_summary']['dlc'][error_key]
            summary['count'] += 1
            if summary['first_ts'] is None:
                summary['first_ts'] = entry.timestamp
                summary['example_line'] = entry.raw_line
                summary['frame_name'] = frame_definition.name
            summary['last_ts'] = entry.timestamp
def validate_lin_checksum(entry: LogEntry, ldf_id_to_frame_map: Dict[int, LDFFrame], log_stats: Dict[str, Any]) -> None:
    if entry.channel != 'LIN' or entry.type.lower() != 'rx' or entry.declared_checksum is None or entry.data is None:
        return
    if not entry.data and entry.csm.lower() != 'enhanced':
        return
    frame_definition = ldf_id_to_frame_map.get(entry.frame_id_int)
    frame_name_for_log = frame_definition.name if frame_definition else entry.frame_id
    data_for_checksum = list(entry.data)
    checksum_type = (entry.csm or '').lower()
    if checksum_type == 'enhanced':
        try:
            pid = calculate_pid(entry.frame_id_int)
            data_for_checksum.insert(0, pid)
        except Exception:
            return
    try:
        expected_checksum = calculate_checksum(data_for_checksum)
    except Exception:
        return
    if expected_checksum != entry.declared_checksum:
        error_key = (entry.frame_id_int, expected_checksum, entry.declared_checksum)
        summary = log_stats['error_summary']['checksum'][error_key]
        summary['count'] += 1
        if summary['first_ts'] is None:
            summary['first_ts'] = entry.timestamp
            summary['example_line'] = entry.raw_line
            summary['frame_name'] = frame_name_for_log
        summary['last_ts'] = entry.timestamp
def extract_signal_value(
    data_bytes,
    start_bit,
    length,
    is_big_endian,
    is_signed,
    signal_name_for_log="UnknownSignal",
    frame_id_for_log="UnknownFrame"
):
    extracted_value = 0
    if is_big_endian:
        for i in range(length):
            bit_index = 8 * (start_bit // 8) + (7 - (start_bit % 8)) + i
            byte_index = bit_index // 8
            bit_in_byte = bit_index % 8
            bit_value = (data_bytes[byte_index] >> (7 - bit_in_byte)) & 1
            extracted_value = (extracted_value << 1) | bit_value
    else:
        raw_value_combined = 0
        for idx, byte in enumerate(data_bytes):
            raw_value_combined |= (byte & 0xFF) << (8 * idx)
        mask = (1 << length) - 1
        extracted_value = (raw_value_combined >> start_bit) & mask
    if is_signed and length > 0:
        sign_bit_mask = 1 << (length - 1)
        if (extracted_value & sign_bit_mask):
            extracted_value -= (1 << length)
    return extracted_value
def update_signal_stats(
    entry: LogEntry,
    frame_definition: Union[LDFFrame, DBCMessage],
    log_stats: Dict[str, Any],
    ldf_signals_by_name: Dict[str, LDFSignal],
    dbc_signals_by_name: Dict[str, DBCSignal],
    ldf_data: LDFData
) -> None:
    if not frame_definition or not entry.data:
        return
    is_lin_frame = isinstance(frame_definition, LDFFrame)
    network_type = "LIN" if is_lin_frame else entry.channel
    frame_id_for_log = f"{network_type}_0x{entry.frame_id_int:X}"
    actual_mux_value: Optional[int] = None
    mux_switch_signal: Optional[DBCSignal] = None
    if not is_lin_frame and isinstance(frame_definition, DBCMessage):
        mux_switch_signal = next((s for s in frame_definition.signals if s.is_multiplexer_switch), None)
        if mux_switch_signal:
            if mux_switch_signal.start_bit is not None and mux_switch_signal.length is not None:
                max_bit_mux = mux_switch_signal.start_bit + mux_switch_signal.length
                required_bytes_mux = (max_bit_mux + 7) // 8
                if len(entry.data) >= required_bytes_mux:
                    try:
                        actual_mux_value = extract_signal_value(
                            entry.data,
                            mux_switch_signal.start_bit,
                            mux_switch_signal.length,
                            mux_switch_signal.is_big_endian,
                            mux_switch_signal.is_signed,
                            signal_name_for_log=f"{mux_switch_signal.name} (MuxSwitch)",
                            frame_id_for_log=frame_id_for_log
                        )
                    except Exception:
                        pass
                else:
                    mux_switch_signal = None 
            else:
                mux_switch_signal = None
    
    # Lógica de verificação de falha do Slave
    if is_lin_frame and frame_definition.publisher:
        publisher_node = frame_definition.publisher
        error_signals_map = ldf_data.nodes.get('slaves_with_error_signal', {})
        
        # Verifica se o nó publicador deste frame tem um sinal de erro configurado
        if publisher_node in error_signals_map:
            error_signal_name = error_signals_map[publisher_node]
            
            # Procura pelo sinal de erro dentro dos sinais deste frame específico
            error_signal_spec = next((s for s in frame_definition.signals if s.name == error_signal_name), None)
            
            if error_signal_spec and error_signal_spec.start_bit is not None and error_signal_spec.length is not None:
                try:
                    error_raw_value = extract_signal_value(
                        entry.data,
                        error_signal_spec.start_bit,
                        error_signal_spec.length,
                        is_big_endian=False, # LIN é sempre little-endian
                        is_signed=False,
                        signal_name_for_log=error_signal_name,
                        frame_id_for_log=frame_id_for_log
                    )
                    
                    if error_raw_value != 0:
                        fault_key = (publisher_node, error_signal_name)
                        fault_stats = log_stats['slave_faults'][fault_key]
                        fault_stats['count'] += 1
                        fault_stats['node_name'] = publisher_node
                        if fault_stats['first_ts'] is None:
                            fault_stats['first_ts'] = entry.timestamp
                        fault_stats['last_ts'] = entry.timestamp
                except (IndexError, TypeError):
                    pass # Ignora se os dados do frame não forem suficientes

    # Lógica de estatísticas de todos os sinais (continua normalmente)
    log_stats.setdefault('signal_stats', defaultdict(lambda: {
        'min_phys': float('inf'), 'max_phys': float('-inf'), 'min_display': None, 'max_display': None,
        'unit': '', 'encoding_type': 'physical', 'first_ts': None, 'last_ts': None, 'count': 0
    }))
    log_stats.setdefault("signal_to_frame_map", {})
    log_stats.setdefault('signal_range_errors', defaultdict(lambda: {
        'out_of_range_count': 0, 'first_ts': None, 'last_ts': None, 'example_value': None
    }))

    for sig_spec in frame_definition.signals:
        if sig_spec.start_bit is None or sig_spec.length is None or sig_spec.length == 0:
            continue
        
        max_bit_pos = sig_spec.start_bit + sig_spec.length
        required_bytes = (max_bit_pos + 7) // 8
        if len(entry.data) < required_bytes:
            continue

        signal_info: Optional[Union[LDFSignal, DBCSignal]] = None
        if is_lin_frame:
            signal_info = ldf_signals_by_name.get(sig_spec.name, sig_spec)
        else: # CAN/CAN-FD
            signal_info = dbc_signals_by_name.get(sig_spec.name)
            if signal_info and signal_info.multiplexer_value is not None:
                if mux_switch_signal is None or actual_mux_value != signal_info.multiplexer_value:
                    continue
        if not signal_info:
            continue
            
        use_big_endian = getattr(signal_info, 'is_big_endian', False) if isinstance(signal_info, DBCSignal) else False
        use_signed = getattr(signal_info, 'is_signed', False)
        
        try:
            raw_value = extract_signal_value(
                entry.data, sig_spec.start_bit, sig_spec.length,
                is_big_endian=use_big_endian, is_signed=use_signed,
                signal_name_for_log=sig_spec.name, frame_id_for_log=frame_id_for_log
            )
        except (IndexError, TypeError):
            continue

        factor = getattr(signal_info, 'factor', 1.0)
        offset = getattr(signal_info, 'offset', 0.0)
        unit = getattr(signal_info, 'unit', '') or ''
        logical_map = getattr(signal_info, 'logical_map', {})
        encoding_type = getattr(signal_info, 'encoding_type', 'physical')
        physical_value = convert_signal_value(raw_value, factor, offset)
        display_value: Union[str, float]
        if encoding_type in ("logical", "hybrid") and raw_value in logical_map:
            display_value = logical_map[raw_value]
        else:
            try:
                display_value = float(f"{physical_value:.6g}")
            except (ValueError, TypeError):
                display_value = physical_value

        if encoding_type == 'physical' or encoding_type == 'hybrid':
            min_val = getattr(signal_info, 'min_value', None)
            max_val = getattr(signal_info, 'max_value', None)
            if min_val is not None and max_val is not None:
                if physical_value < min_val or physical_value > max_val:
                    range_error_key = (network_type, sig_spec.name)
                    range_error = log_stats['signal_range_errors'][range_error_key]
                    range_error['out_of_range_count'] += 1
                    if range_error['first_ts'] is None:
                        range_error['first_ts'] = entry.timestamp
                        range_error['example_value'] = physical_value
                    range_error['last_ts'] = entry.timestamp
                    
        stats_key = (network_type, sig_spec.name)
        stats = log_stats['signal_stats'][stats_key]
        if stats['count'] == 0:
            stats['min_phys'] = physical_value
            stats['max_phys'] = physical_value
            stats['min_display'] = display_value
            stats['max_display'] = display_value
            stats['unit'] = unit
            stats['encoding_type'] = encoding_type
            stats['first_ts'] = entry.timestamp
            log_stats["signal_to_frame_map"][stats_key] = frame_definition.name
        if physical_value < stats['min_phys']:
            stats['min_phys'] = physical_value
            stats['min_display'] = display_value
        if physical_value > stats['max_phys']:
            stats['max_phys'] = physical_value
            stats['max_display'] = display_value
        stats['last_ts'] = entry.timestamp
        stats['count'] += 1
def validate_id_parity(entry: LogEntry, log_stats: Dict[str, Any]) -> None:
    pid = entry.frame_id_int
    if entry.channel != 'LIN' or pid < 0x40:
        return
    raw_id = pid & 0x3F
    p0 = ((raw_id >> 0) ^ (raw_id >> 1) ^ (raw_id >> 2) ^ (raw_id >> 4)) & 1
    p1 = (~((raw_id >> 1) ^ (raw_id >> 3) ^ (raw_id >> 4) ^ (raw_id >> 5))) & 1
    expected_pid = raw_id | (p0 << 6) | (p1 << 7)
    if expected_pid != pid:
        summary = log_stats.setdefault('error_summary', {}) \
                           .setdefault('parity', defaultdict(lambda: {'count': 0, 'first_ts': None, 'last_ts': None}))
        rec = summary[pid]
        rec['count'] += 1
        if rec['first_ts'] is None:
            rec['first_ts'] = entry.timestamp
            rec['example_line'] = entry.raw_line
        rec['last_ts'] = entry.timestamp
def parse_log(log_path: str) -> Iterator[LogEntry]:
    """
    Faz parsing de arquivo de log de comunicação CAN/LIN.
    
    Suporta múltiplos formatos:
    - Vector ASC
    - PCAN TRC
    - Formato CSV customizado
    - Formato de log genérico com timestamp
    
    Args:
        log_path (str): Caminho para o arquivo de log
    
    Returns:
        List[LogEntry]: Lista ordenada de entradas de log por timestamp
    
    Exemplo de formato suportado:
        0.123456 Rx 1 0x12 8 01 02 03 04 05 06 07 08
    """
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as log_file:
            while True:
                try:
                    line = log_file.readline()
                except Exception:
                    continue
                if not line:
                    break
                raw_line_stripped = line.strip()
                if not raw_line_stripped:
                    continue
                log_entry: Optional[LogEntry] = None
                m_spike = SPIKE_PATTERN.match(raw_line_stripped)
                m_transerr = TRANSERR_PATTERN.match(raw_line_stripped)
                m_rcverr = RCVERR_PATTERN.match(raw_line_stripped)
                m_lin = LIN_PATTERN.match(raw_line_stripped)
                m_event = EVENT_PATTERN.match(raw_line_stripped)
                m_canfd = CANFD_PATTERN.match(raw_line_stripped)
                m_can = CAN_PATTERN.match(raw_line_stripped)
                try:
                    if m_spike:
                        match_dict = m_spike.groupdict()
                        log_entry = LogEntry(
                            timestamp=float(match_dict['ts']),
                            channel='LIN', frame_id='Spike', frame_id_int=-1,
                            type='Spike', data=[], raw_line=raw_line_stripped
                        )
                    elif m_transerr or m_rcverr:
                        match_dict = (m_transerr or m_rcverr).groupdict()
                        err_type = 'TransmErr' if m_transerr else 'RcvError'
                        frame_id_str = match_dict.get('id') or err_type
                        frame_id_int = -1
                        if frame_id_str and frame_id_str != err_type:
                             try: frame_id_int = int(frame_id_str, 16)
                             except ValueError: pass

                        full_time_val = None
                        header_time_val = None
                        if match_dict.get('full_time'):
                            try: full_time_val = float(match_dict['full_time'])
                            except ValueError: pass
                        if match_dict.get('header_time'):
                            try: header_time_val = float(match_dict['header_time'])
                            except ValueError: pass

                        log_entry = LogEntry(
                            timestamp=float(match_dict['ts']),
                            channel='LIN', frame_id=frame_id_str, frame_id_int=frame_id_int,
                            type=err_type, data=[], raw_line=raw_line_stripped,
                            full_time_tbit=full_time_val, header_time_tbit=header_time_val
                        )
                    elif m_lin:
                        match_dict = m_lin.groupdict()
                        frame_id_str = match_dict['id']
                        frame_id_int = int(frame_id_str, 16)
                        data_bytes = [int(b, 16) for b in match_dict['data'].strip().split()] if match_dict['data'] else []
                        checksum_val = int(match_dict['checksum'], 16) if match_dict.get('checksum') else None
                        
                        physical_metadata = {k: match_dict[k] for k in ['sof', 'br', 'break_info', 'eoh', 'eob', 'eof', 'rbr', 'hbr', 'hso', 'rso'] if match_dict.get(k)}
                        
                        full_time_val = float(match_dict['full_time']) if match_dict.get('full_time') else None
                        header_time_val = float(match_dict['header_time']) if match_dict.get('header_time') else None

                        log_entry = LogEntry(
                            timestamp=float(match_dict['ts']),
                            channel='LIN', frame_id=frame_id_str, frame_id_int=frame_id_int,
                            type=match_dict['type'], data=data_bytes, raw_line=raw_line_stripped,
                            declared_checksum=checksum_val, csm=match_dict.get('csm'),
                            physical_metadata=physical_metadata if physical_metadata else None,
                            full_time_tbit=full_time_val, header_time_tbit=header_time_val
                        )
                    elif m_canfd:
                        match_dict = m_canfd.groupdict()
                        log_entry = LogEntry(
                            timestamp=float(match_dict['ts']), channel=f"CANFD{match_dict['channel']}",
                            frame_id=match_dict['id'], frame_id_int=int(match_dict['id'], 16),
                            type=match_dict['type'], data=[int(b, 16) for b in match_dict['data'].strip().split()] if match_dict.get('data') else [],
                            raw_line=raw_line_stripped
                        )
                    elif m_can:
                        match_dict = m_can.groupdict()
                        frame_id_str_numeric = match_dict['id'].lower().rstrip('x')
                        log_entry = LogEntry(
                            timestamp=float(match_dict['ts']), channel=f"CAN{match_dict['channel']}",
                            frame_id=match_dict['id'], frame_id_int=int(frame_id_str_numeric, 16),
                            type=match_dict['type'], data=[int(b, 16) for b in match_dict['data'].strip().split()] if match_dict.get('data') else [],
                            raw_line=raw_line_stripped
                        )
                    elif m_event:
                        match_dict = m_event.groupdict()
                        log_entry = LogEntry(
                            timestamp=float(match_dict['ts']), channel='LIN', frame_id='SleepModeEvent',
                            frame_id_int=-1, type='SleepModeEvent', data=[], raw_line=raw_line_stripped,
                            event_channel=int(match_dict['event_channel']) if match_dict.get('event_channel') else None
                        )
                except (ValueError, TypeError, KeyError):
                    log_entry = None
                if log_entry:
                    yield log_entry
        sys.stdout.write("\n")
        sys.stdout.flush()
    except FileNotFoundError:
        raise
    except Exception as e:
        raise
def validate_timestamp_sync(
    current_timestamp: float,
    last_valid_timestamp: Optional[float],
    log_stats: Dict[str, Any]
) -> Optional[float]:
    if last_valid_timestamp is None:
        return current_timestamp
    delta = current_timestamp - last_valid_timestamp
    error_type = None
    details = {}
    if delta < -1e-9:
        error_type = 'negative_jump'
        details = {'prev': last_valid_timestamp, 'current': current_timestamp, 'delta': delta}
    if error_type:
        log_stats.setdefault('error_summary', {}).setdefault('sync', {})
        summary = log_stats['error_summary']['sync'].setdefault(
            error_type,
            {'count': 0, 'first_ts': None, 'last_ts': None, 'example_details': None}
        )
        summary['count'] += 1
        if summary['first_ts'] is None:
            summary['first_ts'] = current_timestamp
            summary['example_details'] = details
        summary['last_ts'] = current_timestamp
    return current_timestamp
def _post_process_gateway_correlation(log_stats, source_events, target_events, config, ldf_data, can_dbcs):
    gateway_tolerance_s = config.get('gateway_tolerance', DEFAULT_GATEWAY_TOLERANCE_S)
    ldf_sigs = {s.name: s for f in ldf_data.frames.values() for s in f.signals}
    dbc_sigs = {sig.name: sig for dbc in can_dbcs.values() for msg in dbc.values() for sig in msg.signals}

    for map_idx, targets in target_events.items():
        sources = source_events.get(map_idx, [])
        if not sources or not targets:
            continue
        
        res = log_stats['gateway_results'][map_idx]
        mapping_info = res.get('mapping_info')
        if not mapping_info: continue

        src_details = _get_comparison_details(mapping_info['source_signal'], mapping_info['source_network'], ldf_sigs, dbc_sigs)
        tgt_details = _get_comparison_details(mapping_info['target_signal'], mapping_info['target_network'], ldf_sigs, dbc_sigs)
        if not src_details or not tgt_details:
            continue

        source_pointer = 0
        num_source_events = len(sources)

        for ts_target, raw_target in targets:
            while source_pointer < num_source_events and sources[source_pointer][0] < (ts_target - gateway_tolerance_s):
                source_pointer += 1

            best_source_candidate = None
            for i in range(source_pointer, num_source_events):
                ts_source, _ = sources[i]
                if ts_source >= ts_target:
                    break
                best_source_candidate = sources[i]

            res['comparisons'] += 1
            if best_source_candidate:
                ts_source, raw_source = best_source_candidate
                latency_s = ts_target - ts_source
                if latency_s >= 0:
                    lat_stats = res['latency_stats']
                    lat_stats['count'] += 1
                    lat_stats['sum'] += latency_s
                    lat_stats['min'] = min(lat_stats['min'], latency_s)
                    lat_stats['max'] = max(lat_stats['max'], latency_s)

                match, c_type = compare_gateway_values(raw_source, raw_target, src_details, tgt_details)
                if match:
                    res['matches'] += 1
                else:
                    key = 'mismatches_type' if c_type == 'hybrid_mismatch' else 'mismatches_value'
                    res[key] += 1
                    res['mismatch_examples'].append({
                        'ts_source': ts_source,
                        'raw_source': raw_source,
                        'phys_source': convert_signal_value(raw_source, src_details['factor'], src_details['offset']),
                        'logical_source': src_details['logical_map'].get(raw_source, '-'),
                        'ts_target': ts_target,
                        'raw_target': raw_target,
                        'phys_target': convert_signal_value(raw_target, tgt_details['factor'], tgt_details['offset']),
                        'logical_target': tgt_details['logical_map'].get(raw_target, '-'),
                        'type': c_type,
                        'latency_ms': latency_s * 1000
                    })
            else:
                res['mismatches_timing'] += 1

def _finalize_statistics(log_stats: Dict[str, Any]):
    finalize_network_cycle_stats(log_stats)
    frame_timing_summary = defaultdict(dict)
    for channel, frames in log_stats.get('frame_timing_stats', {}).items():
        for frame_id, stats in frames.items():
            if stats.get('delta_count', 0) > 0:
                avg_ms = (stats['sum_delta'] / stats['delta_count']) * 1000
                min_ms = stats['min_delta'] * 1000
                max_ms = stats['max_delta'] * 1000
                frame_timing_summary[channel][frame_id] = {'name': stats['frame_name'], 'count': stats['count'], 'min_ms': min_ms, 'max_ms': max_ms, 'avg_ms': avg_ms}
    log_stats['frame_timing_summary'] = frame_timing_summary
    
    log_info = log_stats.get('log_info', {})
    duration = 0.0
    if log_info.get('end_time') and log_info.get('start_time'):
        duration = log_info['end_time'] - log_info['start_time']
        log_stats['log_info']['duration'] = duration
    bl_stats = log_stats.get('lin_bus_load', {})
    bl_stats['duration_analyzed_s'] = duration
    if duration > 0:
        bl_stats['percentage'] = (bl_stats.get('total_busy_time_s', 0) / duration) * 100
        if bl_stats['bus_load_by_window']:
            bl_stats['average_percentage'] = sum(bl_stats['bus_load_by_window']) / len(bl_stats['bus_load_by_window'])
            bl_stats['max_percentage'] = max(bl_stats['bus_load_by_window'])
        else:
            bl_stats['average_percentage'] = bl_stats['percentage']
            bl_stats['max_percentage'] = bl_stats['percentage']

    node_bus_load_percentage = {}
    for node_name, stats in log_stats.get('node_timing_stats', {}).items():
        node_busy_time_s = stats.get('bus_load_s', 0.0)
        node_bus_load_percentage[node_name] = (node_busy_time_s / duration) * 100 if duration > 0 else 0.0
    log_stats['node_bus_load_percentage'] = node_bus_load_percentage

    for idx, res in log_stats.get('gateway_results', {}).items():
        latency_stats = res.get('latency_stats', {})
        if latency_stats.get('count', 0) > 0:
            latency_stats['average'] = latency_stats['sum'] / latency_stats['count']
        else:
            latency_stats['average'] = None
def process_log_file(log_path: str, ldf_data: LDFData, can_dbcs: Dict[str, Dict[int, DBCMessage]], gateway_lookup: Dict[str, Any], config: Dict[str, Any], progress_callback=None):
    """
    Função principal que orquestra todo o processo de análise.
    
    Pipeline de análise:
    1. Carregar e parsear arquivos de configuração (LDF/DBC)
    2. Parsear arquivo de log
    3. Executar todas as validações em paralelo:
       - Checksums
       - Timing
       - Camada física
       - Schedule adherence
       - Gateway mapping
    4. Agregar resultados
    5. Gerar relatório HTML
    6. Retornar dicionário com métricas
    
    Args:
        ldf_path (str): Caminho para arquivo LDF
        dbc_path (str): Caminho para arquivo DBC
        log_path (str): Caminho para log de comunicação
        output_path (str): Caminho para salvar relatório
        config (Dict): Configurações opcionais para override de thresholds
    
    Returns:
        Dict: Resultados agregados da análise
        {
            'total_frames': int,
            'error_count': int,
            'pass_rate': float,
            'critical_issues': [...],
            'warnings': [...]
        }
    
    Raises:
        FileNotFoundError: Se arquivos de entrada não existirem
        ValueError: Se formato de arquivo for inválido
    
    Exemplo de uso:
        results = process_log_file(
            ldf_path='network.ldf',
            dbc_path='powertrain.dbc',
            log_path='test_session_001.asc',
            output_path='analysis_report.html'
        )
        
        if results['pass_rate'] < 0.95:
            print(f"Análise falhou: {results['error_count']} erros")
    """
    log_stats = initialize_log_stats(config)
    gateway_source_events = defaultdict(list)
    gateway_target_events = defaultdict(list)
    ldf_id_to_frame = {f.id: f for f in ldf_data.frames.values() if f.id is not None}
    ldf_sigs = {s.name: s for f in ldf_data.frames.values() for s in f.signals} if ldf_data else {}
    dbc_sigs = {sig.name: sig for dbc in can_dbcs.values() for msg in dbc.values() for sig in msg.signals}
    valid_can_channels = set(can_dbcs.keys())
    
    bus_load_window_s = config.get('bus_load_window_s', DEFAULT_BUS_LOAD_WINDOW_S)
    lin_baudrate = config.get('lin_baudrate', DEFAULT_LIN_BAUDRATE)
    time_in_window_us = defaultdict(float)
    current_window_index = -1
    start_ts = None

    for entry in parse_log(log_path):
        ts = entry.timestamp
        log_stats['_internal_parse_stats']['processed'] += 1
        
        if start_ts is None:
            start_ts = ts
            log_stats['log_info']['start_time'] = ts
        
        log_stats['log_info']['end_time'] = ts

        if entry.channel == 'LIN':
            frame_duration_s = None
            if lin_baudrate > 0:
                if entry.type.lower() == 'rx':
                    if entry.full_time_tbit is not None:
                        frame_duration_s = entry.full_time_tbit / lin_baudrate
                    else:
                        num_bits = 34 + (len(entry.data) + 1) * 10
                        frame_duration_s = num_bits / lin_baudrate
                
                elif entry.type.lower() in ('transmerr', 'rcverror'):
                    if entry.header_time_tbit is not None:
                        frame_duration_s = entry.header_time_tbit / lin_baudrate
                    else:
                        frame_duration_s = 34 / lin_baudrate

            if frame_duration_s is not None:
                frame_duration_us = frame_duration_s * 1_000_000
                window_index = int((ts - start_ts) / bus_load_window_s)

                if window_index > current_window_index:
                    if current_window_index != -1:
                        load_perc = (time_in_window_us[current_window_index] / (bus_load_window_s * 1e6)) * 100
                        log_stats['lin_bus_load']['bus_load_by_window'].append(load_perc)
                    
                    for _ in range(current_window_index + 1, window_index):
                        log_stats['lin_bus_load']['bus_load_by_window'].append(0.0)
                    current_window_index = window_index
                
                time_in_window_us[window_index] += frame_duration_us
                log_stats['lin_bus_load']['total_busy_time_s'] += frame_duration_s
        
        if entry.channel.startswith('CAN') and entry.channel not in valid_can_channels:
            log_stats['_internal_parse_stats']['skipped'] += 1
            continue
            
        update_network_cycle_state(entry, ldf_data, ldf_id_to_frame, log_stats)
        frame_def = None
        net_type = entry.channel
        
        if entry.channel == 'LIN':
            log_stats['log_info']['lin_entries'] += 1
            frame_def = ldf_id_to_frame.get(entry.frame_id_int)
            validate_lin_ids_and_dlcs(entry, ldf_id_to_frame, log_stats)
            validate_transmission_errors(entry, log_stats)
            validate_id_parity(entry, log_stats)
            if config.get('enable_checksum_validation', True):
                validate_lin_checksum(entry, ldf_id_to_frame, log_stats)
            
            if config.get('enable_physical_validation', True):
                if entry.physical_metadata:
                    validate_physical_layer(entry, entry.physical_metadata, log_stats, ldf_id_to_frame, ldf_data, config)
                    update_slave_response_stats(entry, ldf_data, ldf_id_to_frame, log_stats)
            
            if config.get('enable_schedule_validation', True) and log_stats.get('network_cycle_state', {}).get('active'):
                validate_schedule_order_and_presence(entry, ldf_data, ldf_id_to_frame, log_stats, config.get('schedule_tolerance_factor', 0.1), config.get('schedule_min_tolerance_s', DEFAULT_SCHEDULE_MIN_ABSOLUTE_TOLERANCE_S))
        
        elif entry.channel.startswith('CAN'):
            log_stats['log_info']['can_entries'] += 1
            frame_def = can_dbcs.get(net_type, {}).get(entry.frame_id_int)
        
        if frame_def and entry.data:
            update_signal_stats(entry, frame_def, log_stats, ldf_sigs, dbc_sigs, ldf_data) 
            update_frame_timing_stats(entry, frame_def, log_stats)
            
        if config.get('enable_gateway_validation') and log_stats.get('network_cycle_state', {}).get('active'):
            src_maps = gateway_lookup.get('source', {}).get(net_type, {}).get(entry.frame_id_int, [])
            for m in src_maps:
                sig_info = m.get('_source_signal_obj')
                if sig_info and sig_info.start_bit is not None and sig_info.length is not None and entry.data:
                    raw_val = extract_signal_value(entry.data, sig_info.start_bit, sig_info.length, getattr(sig_info, 'is_big_endian', False), getattr(sig_info, 'is_signed', False))
                    gateway_source_events[m['map_index']].append((ts, raw_val))
                    res = log_stats['gateway_results'][m['map_index']]
                    if res['mapping_info'] is None: res['mapping_info'] = m.copy()
            tgt_maps = gateway_lookup.get('target', {}).get(net_type, {}).get(entry.frame_id_int, [])
            for m in tgt_maps:
                sig_info = m.get('_target_signal_obj')
                if sig_info and sig_info.start_bit is not None and sig_info.length is not None and entry.data:
                    raw_val = extract_signal_value(entry.data, sig_info.start_bit, sig_info.length, getattr(sig_info, 'is_big_endian', False), getattr(sig_info, 'is_signed', False))
                    gateway_target_events[m['map_index']].append((ts, raw_val))
                    res = log_stats['gateway_results'][m['map_index']]
                    if res['mapping_info'] is None: res['mapping_info'] = m.copy()

    if start_ts is not None:
        if current_window_index != -1:
            load_perc = (time_in_window_us[current_window_index] / (bus_load_window_s * 1e6)) * 100
            log_stats['lin_bus_load']['bus_load_by_window'].append(load_perc)

        total_duration = log_stats['log_info']['end_time'] - start_ts
        total_windows_expected = int(total_duration / bus_load_window_s)
        
        num_windows_so_far = len(log_stats['lin_bus_load']['bus_load_by_window'])
        for _ in range(num_windows_so_far, total_windows_expected + 1):
             log_stats['lin_bus_load']['bus_load_by_window'].append(0.0)

    if config.get('enable_gateway_validation'):
        _post_process_gateway_correlation(log_stats, gateway_source_events, gateway_target_events, config, ldf_data, can_dbcs)
    
    _finalize_statistics(log_stats)
    return log_stats
def _write_node_performance_section(write_html, log_stats):
    node_stats = log_stats.get('node_response_stats')
    if not node_stats:
        return
    write_html("<h2>Performance Analysis</h2>")
    write_html("<details close><summary>Slave Response Time</summary>")
    write_html("<table><thead><tr><th>Slave Node</th><th>Frames Published</th><th>Min. Response (µs)</th><th>Max. Response (µs)</th><th>Avg. Response (µs)</th></tr></thead><tbody>")
    SLOW_RESPONSE_THRESHOLD_US = 1000.0
    for node_name, stats in sorted(node_stats.items()):
        if stats['count'] > 0:
            avg_us = (stats['sum_s'] / stats['count']) * 1_000
            min_us = stats['min_s'] * 1_000
            max_us = stats['max_s'] * 1_000
            max_tag = tag('WARN', f"{max_us:.1f}") if max_us > SLOW_RESPONSE_THRESHOLD_US else f"{max_us:.1f}"
            write_html(f"<tr><td><code>{escape(node_name)}</code></td><td>{stats['frames_published']}</td><td>{min_us:.1f}</td><td>{max_tag}</td><td>{avg_us:.1f}</td></tr>")
        elif stats['frames_published'] > 0:
            write_html(f"<tr><td><code>{escape(node_name)}</code></td><td>{stats['frames_published']}</td><td>N/A</td><td>N/A</td><td>N/A</td></tr>")
    write_html("</tbody></table></details>")
def _write_report_header(write_html, log_stats):
    log_file_name_for_title = escape(os.path.basename(log_stats.get('config_used', {}).get('log_file', '-')))
    write_html(f"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
    write_html(f"<title>{SCRIPT_NAME} Report - {log_file_name_for_title}</title>")
    write_html(LINSPECTOR_CSS)
    write_html("</head><body>")
    write_html("""
        <div class="report-header">
            <span class="report-title">LIN Analysis Report</span>
        </div>
    """)
def _write_slave_fault_details(write_html, log_stats):
    slave_faults = log_stats.get('slave_faults')
    if not any(details.get('count', 0) > 0 for details in slave_faults.values()):
        return
    write_html("<details close><summary>Slave Faults Detected</summary>")
    write_html("<table><thead><tr><th>Slave Node</th><th>Error Signal Name</th><th>Times Reported</th><th>First Timestamp (s)</th><th>Last Timestamp (s)</th></tr></thead><tbody>")
    sorted_faults = sorted(slave_faults.items(), key=lambda item: item[0][0])
    for (node_name, signal_name), details in sorted_faults:
        if details['count'] > 0:
            write_html(f"<tr>"
                       f"<td><code>{escape(node_name)}</code></td>"
                       f"<td><code>{escape(signal_name)}</code></td>"
                       f"<td>{details['count']}</td>"
                       f"<td>{details.get('first_ts', 0):.6f}</td>"
                       f"<td>{details.get('last_ts', 0):.6f}</td>"
                       f"</tr>")
        
    write_html("</tbody></table></details>")
def _write_summary_tables(write_html, log_stats, args, can_dbcs, ldf_data: LDFData):
    def filename(p):
        if not p: return '-'
        if isinstance(p, list): return ", ".join(os.path.basename(path) for path in p) if p else '-'
        return os.path.basename(p) if p else '-'
    config_used = log_stats.get('config_used', {})
    write_html("<h2>General Summary</h2>")
    write_html("<table><thead><tr><th colspan='2'>Configuration / Data LOG</th></tr></thead><tbody>")
    write_html(f"<tr><td>LDF File</td><td><code>{escape(filename(config_used.get('ldf_file')))}</code></td></tr>")
    for ch_name in sorted(can_dbcs.keys()):
        dbc_files = args.dbc_files.get(ch_name, [])
        if dbc_files:
            write_html(f"<tr><td>DBC {ch_name}</td><td><code>{escape(filename(dbc_files))}</code></td></tr>")
    if config_used.get('gateway_map_file'):
        write_html(f"<tr><td>Gateway Map File</td><td><code>{escape(filename(config_used.get('gateway_map_file')))}</code></td></tr>")
    write_html(f"<tr><td>LOG File</td><td><code>{escape(filename(config_used.get('log_file')))}</code></td></tr>")
    write_html(f"<tr><td>Total Log Lines Parsed</td><td>{log_stats['_internal_parse_stats'].get('processed', 0)}</td></tr>")
    write_html("</tbody></table>")
    err_sum = log_stats.get('error_summary', {})
    val_stat = {}
    phys_ec = sum(d.get('count', 0) for edt in log_stats.get('physical_errors', {}).values() for d in edt.values())
    val_stat['LIN Physical Layer'] = ('KO' if phys_ec > 0 else 'OK', phys_ec) if config_used.get('enable_physical_validation') else ('NA', 'Disabled')
    par_ec = sum(v.get('count', 0) for v in err_sum.get('parity', {}).values())
    val_stat['LIN PID Parity'] = ('KO' if par_ec > 0 else 'OK', par_ec)
    dlc_ec = sum(v.get('count', 0) for v in err_sum.get('dlc', {}).values())
    val_stat['LIN DLC'] = ('KO' if dlc_ec > 0 else 'OK', dlc_ec)
    cks_ec = sum(v.get('count', 0) for v in err_sum.get('checksum', {}).values())
    val_stat['LIN Checksum'] = ('KO' if cks_ec > 0 else 'OK', cks_ec) if config_used.get('enable_checksum_validation') else ('NA', 'Disabled')
    trn_ec = sum(v.get('count', 0) for v in err_sum.get('transmission', {}).values())
    val_stat['Transmission Errors'] = ('WARN' if trn_ec > 0 else 'OK', trn_ec)
    faults_ec = sum(v.get('count', 0) for v in log_stats.get('slave_faults', {}).values())
    val_stat['Slave Faults Detected'] = ('KO' if faults_ec > 0 else 'OK', faults_ec)
    has_timing_mismatches = any(stats['count'] > 0 for stats in log_stats.get('schedule_timing_mismatches', {}).values())
    has_sequence_errors = False
    schedule_analysis_log = log_stats.get('schedule_analysis', {})
    if schedule_analysis_log.get('global_errors'):
        has_sequence_errors = True
    else:
        for cycle in schedule_analysis_log.get('cycles', []):
            if any(evt['type'] not in ('Cycle Start', 'Cycle Completed') for evt in cycle.get('events', [])):
                has_sequence_errors = True
                break
    total_schedule_errors = 0
    if has_timing_mismatches:
        total_schedule_errors += sum(1 for stats in log_stats.get('schedule_timing_mismatches', {}).values() if stats['count'] > 0)
    if has_sequence_errors:
        total_schedule_errors += len(schedule_analysis_log.get('global_errors', []))
        total_schedule_errors += sum(1 for c in schedule_analysis_log.get('cycles', []) if c.get('status') == 'Aborted')
    is_schedule_failed = has_timing_mismatches or has_sequence_errors
    sch_st = 'KO' if is_schedule_failed else 'OK'
    sch_disp = total_schedule_errors if is_schedule_failed else "-"
    val_stat['LIN Schedule Timing'] = (sch_st, sch_disp) if config_used.get('enable_schedule_validation') else ('NA', 'Disabled')
    net_cyc_sum = log_stats.get('network_cycle_summary', {})
    cyc_ko_c = net_cyc_sum.get('cycles_incomplete', 0) + net_cyc_sum.get('cycles_no_master_response', 0)
    val_stat['LIN Network Cycles'] = ('KO' if cyc_ko_c > 0 else 'OK', cyc_ko_c)
    rng_ec = sum(v.get('out_of_range_count', 0) for v in log_stats.get('signal_range_errors', {}).values())
    val_stat['Signals Out of Range'] = ('KO' if rng_ec > 0 else 'OK', rng_ec)
    foreign_lc = sum(v.get('count', 0) for v in log_stats.get('foreign_ids_summary', {}).get('lin', {}).values())
    val_stat['Foreign LIN IDs'] = ('WARN' if foreign_lc > 0 else 'OK', foreign_lc)
    gw_res = log_stats.get('gateway_results', {})
    gw_val_mm = sum(r.get('mismatches_value', 0) + r.get('mismatches_type', 0) for r in gw_res.values())
    gw_tot_comp = sum(r.get('comparisons', 0) for r in gw_res.values())
    if not config_used.get('enable_gateway_validation'):
        gw_st_val, gw_disp = 'NA', 'Disabled'
    elif gw_tot_comp == 0:
        gw_st_val, gw_disp = 'INFO', 'No Comparisons'
    else:
        gw_st_val, gw_disp = ('KO', gw_val_mm) if gw_val_mm > 0 else ('OK', '-')
    val_stat['Gateway: Value Mismatches'] = (gw_st_val, gw_disp)
    write_html("<table><thead><tr><th>Check</th><th>Status</th><th>Occurrences</th></tr></thead><tbody>")
    val_order = ['LIN Physical Layer', 'LIN PID Parity', 'LIN DLC', 'LIN Checksum', 'Transmission Errors', 'LIN Schedule Timing', 'LIN Network Cycles', 'Signals Out of Range', 'Slave Faults Detected', 'Foreign LIN IDs', 'Gateway: Value Mismatches']
    for n_val in val_order:
        st_val, err_val_raw = val_stat.get(n_val, ("NA", 0))
        disp_err_val = str(err_val_raw) if isinstance(err_val_raw, int) and err_val_raw > 0 else (err_val_raw if isinstance(err_val_raw, str) else "-")
        write_html(f"<tr><td>{escape(n_val)}</td><td>{tag(st_val)}</td><td>{disp_err_val}</td></tr>")
    write_html("</tbody></table>")
def _write_statistics_section(write_html, log_stats, ldf_data):
    write_html("<h2>Statistics</h2>")
    bus_li = log_stats.get('lin_bus_load', {})
    config_used = log_stats.get('config_used', {})
    write_html("<details close><summary>LIN Bus Load Analysis</summary>")
    write_html("<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>")
    write_html(f"<tr><td>Nominal Baudrate</td><td>{bus_li.get('baudrate', DEFAULT_LIN_BAUDRATE)} bps</td></tr>")
    write_html(f"<tr><td>Analysis Duration</td><td>{bus_li.get('duration_analyzed_s', 0.0):.3f} s</td></tr>")
    write_html(f"<tr><td>Overall Bus Load (Goodput)</td><td>{bus_li.get('percentage', 0.0):.2f}%</td></tr>")
    window_s = config_used.get('bus_load_window_s', DEFAULT_BUS_LOAD_WINDOW_S)
    write_html(f"<tr><td>Average Bus Load (per {window_s}s window)</td><td>{bus_li.get('average_percentage', 0.0):.2f}%</td></tr>")
    write_html(f"<tr><td>Peak Bus Load (per {window_s}s window)</td><td>{bus_li.get('max_percentage', 0.0):.2f}%</td></tr>")
    write_html("</tbody></table>")
    bus_load_data = bus_li.get('bus_load_by_window', [])
    if bus_load_data:
        plot_base64 = _generate_bus_load_plot_base64(bus_load_data, window_s)
        if plot_base64:
            write_html(f'<h4>Bus Load Over Time</h4>')
            write_html(f'<div style="text-align: center; margin-top: 10px; margin-bottom: 20px; background-color: white; padding: 10px;">')
            write_html(f'<img src="{plot_base64}" alt="LIN Bus load" style="max-width: 100%; height: auto;"/>')
            write_html(f'</div>')
    write_html("</details>")
    ft_sum = log_stats.get('frame_timing_summary', {})
    lin_timing_data = ft_sum.get('LIN')
    if lin_timing_data:
        sorted_frame_ids = sorted(lin_timing_data.keys())
        write_html(f"<details><summary>LIN Frame Timing</summary><table>")
        write_html("<tr><th>ID</th><th>Name</th><th>Occurrences</th><th>Min Interval (ms)</th><th>Max Interval (ms)</th><th>Average Interval (ms)</th></tr>")
        for frame_id in sorted_frame_ids:
             stats = lin_timing_data[frame_id]
             min_str = f"{stats['min_ms']:.3f}" if stats.get('min_ms') is not None else "-"
             max_str = f"{stats['max_ms']:.3f}" if stats.get('max_ms') is not None else "-"
             avg_str = f"{stats['avg_ms']:.3f}" if stats.get('avg_ms') is not None else "-"
             write_html(f"<tr><td><code>0x{frame_id:X}</code></td><td><code>{escape(stats.get('name', '-'))}</code></td><td>{stats.get('count', 0)}</td><td>{min_str}</td><td>{max_str}</td><td>{avg_str}</td></tr>")
        write_html("</table></details>")
    sig_stats = log_stats.get('signal_stats', {})
    sig_to_fm = log_stats.get('signal_to_frame_map', {})
    if sig_stats and sig_to_fm:
        frames_with_signals = defaultdict(list)
        for (network_type, sig_name), stats_data in sig_stats.items():
            if network_type == 'LIN':
                if frame_name := sig_to_fm.get((network_type, sig_name)):
                    frames_with_signals[frame_name].append({'name': sig_name, **stats_data})
        if frames_with_signals:
            write_html(f"<details><summary>LIN Signals</summary>")
            for frame_name in sorted(frames_with_signals.keys()):
                signals_in_frame = sorted(frames_with_signals[frame_name], key=lambda s: s['name'])
                if not signals_in_frame: continue
                frame_obj_for_id = ldf_data.frames.get(frame_name)
                frame_id_display = f"(0x{frame_obj_for_id.id:X})" if frame_obj_for_id and frame_obj_for_id.id is not None else ""
                write_html(f"<details close><summary>Frame: {escape(frame_name)} {escape(frame_id_display)}</summary>")
                write_html("<table><thead><tr><th>Signal</th><th>Min Display</th><th>Max Display</th><th>Unit</th><th>Encoding</th></tr></thead><tbody>")
                for stats in signals_in_frame:
                    min_d = "Not seen" if stats.get('min_display') is None else escape(str(stats.get('min_display')))
                    max_d = "Not seen" if stats.get('max_display') is None else escape(str(stats.get('max_display')))
                    write_html(f"<tr><td><code>{escape(stats['name'])}</code></td><td><code>{min_d}</code></td><td><code>{max_d}</code></td><td>{escape(stats.get('unit', ''))}</td><td><code>{escape(stats.get('encoding_type', 'physical'))}</code></td></tr>")
                write_html("</tbody></table></details>")
            write_html("</details>")
    net_cyc_sum = log_stats.get('network_cycle_summary', {})
    if net_cyc_sum:
        write_html(f"<details close><summary>LIN Network Cycles Summary</summary><table>")
        mrd_stats = net_cyc_sum.get('master_response_delays_ms_stats', {})
        mrd_count = mrd_stats.get('count',0)
        mrd_min = f"{mrd_stats.get('min',0):.3f}" if mrd_count > 0 else "-"
        mrd_max = f"{mrd_stats.get('max',0):.3f}" if mrd_count > 0 else "-"
        mrd_avg = f"{(mrd_stats.get('sum',0)/mrd_count):.3f}" if mrd_count > 0 else "-"
        def tag_cycle(key, text):
            return tag('KO' if net_cyc_sum.get(key, 0) > 0 else 'OK', text)
        write_html(f"<tr><td>Total Cycles Detected</td><td>{net_cyc_sum.get('total_cycles_detected',0)}</td></tr>")
        write_html(f"<tr><td>Cycles Completed</td><td>{net_cyc_sum.get('cycles_completed',0)}</td></tr>")
        write_html(f"<tr><td>Cycles Incomplete</td><td>{tag_cycle('cycles_incomplete', net_cyc_sum.get('cycles_incomplete',0))}</td></tr>")
        write_html(f"<tr><td>Cycles with No Master Response</td><td>{tag_cycle('cycles_no_master_response', net_cyc_sum.get('cycles_no_master_response',0))}</td></tr>")
        write_html(f"<tr><td>Master Response Delay (ms) (Min/Avg/Max)</td><td>{mrd_min} / {mrd_avg} / {mrd_max} (from {mrd_count} cycles)</td></tr>")
        write_html("</table></details>")
def _write_error_details_section(write_html, log_stats, ldf_data):
    err_sum = log_stats.get('error_summary', {})
    config_used = log_stats.get('config_used', {})
    phys_ec = sum(d.get('count', 0) for edt in log_stats.get('physical_errors', {}).values() for d in edt.values()) if config_used.get('enable_physical_validation') else 0
    par_ec = sum(v.get('count', 0) for v in err_sum.get('parity', {}).values())
    dlc_ec = sum(v.get('count', 0) for v in err_sum.get('dlc', {}).values())
    cks_ec = sum(v.get('count', 0) for v in err_sum.get('checksum', {}).values()) if config_used.get('enable_checksum_validation') else 0
    trn_ec = sum(v.get('count', 0) for v in err_sum.get('transmission', {}).values())
    fas_c = sum(v.get('count', 0) for v in err_sum.get('frames_after_sleep', {}).values())
    sch_ko_c = sum(v.get('count', 0) for iss in log_stats.get('schedule_summary', {}).values() for st, v in iss.items() if st[0] == 'KO')
    foreign_lc = sum(v.get('count', 0) for v in log_stats.get('foreign_ids_summary', {}).get('lin', {}).values())
    rng_ec = sum(v.get('out_of_range_count', 0) for v in log_stats.get('signal_range_errors', {}).values())
    syn_ec = sum(v.get('count', 0) for v in err_sum.get('sync', {}).values())
    any_errors = any([phys_ec, par_ec, dlc_ec, cks_ec, trn_ec, fas_c, sch_ko_c, foreign_lc, rng_ec, syn_ec])
    if not any_errors:
        return
    write_html("<h2>Details of Failed Validations</h2>")
    def write_error_table_if_present(error_data, writer_func, *extra_args):
        if any(d.get('count', 0) > 0 for d in error_data.values()):
            writer_func(write_html, error_data, *extra_args)
    if config_used.get('enable_physical_validation', True) and phys_ec > 0:
        _write_physical_errors(write_html, log_stats, ldf_data)
    write_error_table_if_present(err_sum.get('parity', {}), _write_parity_errors)
    write_error_table_if_present(err_sum.get('dlc', {}), _write_dlc_errors, ldf_data)
    if config_used.get('enable_checksum_validation', True):
        write_error_table_if_present(err_sum.get('checksum', {}), _write_checksum_errors, ldf_data)
    write_error_table_if_present(err_sum.get('transmission', {}), _write_transmission_errors)
    write_error_table_if_present(err_sum.get('frames_after_sleep', {}), _write_frames_after_sleep_errors)
    if sch_ko_c > 0:
        _write_schedule_errors(write_html, log_stats)
    if foreign_lc > 0:
        _write_foreign_id_errors(write_html, log_stats)
    if rng_ec > 0:
        _write_range_errors(write_html, log_stats)
    write_error_table_if_present(err_sum.get('sync', {}), _write_sync_errors)
def _write_transmission_errors(write_html, transmission_errors):
    write_html("<details close><summary>Transmission Errors</summary><table>")
    write_html("<thead><tr><th>Error Type</th><th>Affected ID</th><th>Occurrences</th><th>First Timestamp (s)</th></tr></thead><tbody>")
    def sort_key(item):
        etype, fid = item[0]
        return (etype, float('inf') if fid is None else fid)
    for (etype, fid), details in sorted(transmission_errors.items(), key=sort_key):
        id_str = 'N/A' if fid is None else f"0x{fid:X}"
        write_html(f"<tr><td><code>{escape(etype)}</code></td><td><code>{id_str}</code></td><td>{details['count']}</td><td>{details.get('first_ts', 0):.6f}</td></tr>")
    write_html("</tbody></table></details>")
def _write_frames_after_sleep_errors(write_html, frames_after_sleep_errors):
    write_html("<details close><summary>LIN Frames Detected After Sleep</summary><table>")
    write_html("<thead><tr><th>Frame ID</th><th>Occurrences</th><th>First Timestamp (s)</th><th>Example Log Line</th></tr></thead><tbody>")
    for fid, details in sorted(frames_after_sleep_errors.items()):
        example_line = details.get('example_line', '')
        line_display = escape(example_line[:150] + '...' if len(example_line) > 150 else example_line)
        write_html(f"<tr><td><code>0x{fid:X}</code></td><td>{details['count']}</td><td>{details.get('first_ts', 0):.6f}</td><td><code>{line_display}</code></td></tr>")
    write_html("</tbody></table></details>")
def _write_schedule_errors(write_html, log_stats):
    sched_sum = log_stats.get('schedule_summary', {})
    if not any(status[0] in ('KO', 'WARN') for issues in sched_sum.values() for status, details in issues.items() if details.get('count', 0) > 0):
        return
    write_html("<details close><summary>LIN Schedule Issues</summary>")
    schedule_issues_grouped = defaultdict(list)
    for table, issues in sorted(sched_sum.items()):
        for status_tuple, details in sorted(issues.items()):
            if details.get('count', 0) > 0 and status_tuple[0] in ('KO', 'WARN'):
                schedule_issues_grouped[table].append((status_tuple, details))
    for table, issues_list in sorted(schedule_issues_grouped.items()):
        write_html(f"<h4>Schedule Table: <code>{escape(table)}</code></h4>")
        write_html("<table><thead><tr><th>Status</th><th>Reason</th><th>Nodes</th><th>Occurrences</th><th>Example Timestamp (s)</th></tr></thead><tbody>")
        for (status, reason), details in issues_list:
            nodes_str = ', '.join(f"<code>{escape(n)}</code>" for n in sorted(details.get('nodes', set()))) or '-'
            write_html(f"<tr><td>{tag(status)}</td><td>{escape(reason)}</td><td>{nodes_str}</td><td>{details['count']}</td><td>{details.get('first_ts_event', 0):.6f}</td></tr>")
        write_html("</tbody></table>")
    write_html("</details>")
def _write_foreign_id_errors(write_html, log_stats):
    foreign_lin = log_stats.get('foreign_ids_summary', {}).get('lin', {})
    if not foreign_lin: return
    write_html("<details close><summary>Foreign LIN IDs</summary><table>")
    write_html("<thead><tr><th>Foreign ID</th><th>Occurrences</th><th>First Occurrence (s)</th><th>Last Occurrence (s)</th></tr></thead><tbody>")
    for fid_str, details in sorted(foreign_lin.items()):
        write_html(f"<tr><td><code>{escape(fid_str)}</code></td><td>{details['count']}</td><td>{details.get('first_ts', 0):.6f}</td><td>{details.get('last_ts', 0):.6f}</td></tr>")
    write_html("</tbody></table></details>")
def _write_range_errors(write_html, log_stats):
    sig_rng_err = log_stats.get('signal_range_errors', {})
    if not sig_rng_err: return
    write_html("<details close><summary>Signals Out of Range</summary><table>")
    write_html("<thead><tr><th>Network</th><th>Signal</th><th>Out of Range Count</th><th>Example Value</th><th>First Seen (s)</th><th>Last Seen (s)</th></tr></thead><tbody>")
    for (network_type, sig_name), details in sorted(sig_rng_err.items()):
        example_val = details.get('example_value')
        val_str = f"{example_val:.6g}" if isinstance(example_val, (float, int)) else escape(str(example_val))
        write_html(f"<tr><td><code>{escape(network_type)}</code></td><td><code>{escape(sig_name)}</code></td><td>{details['out_of_range_count']}</td><td><code>{val_str}</code></td><td>{details.get('first_ts', 0):.6f}</td><td>{details.get('last_ts', 0):.6f}</td></tr>")
    write_html("</tbody></table></details>")
def _write_sync_errors(write_html, sync_errors):
    if not sync_errors: return
    write_html("<details close><summary>Timestamp Synchronization Issues</summary><table>")
    write_html("<thead><tr><th>Issue Type</th><th>Occurrences</th><th>Example Details</th><th>First Timestamp (s)</th></tr></thead><tbody>")
    for err_type, details in sorted(sync_errors.items()):
        example_details = details.get('example_details', {})
        details_str = ", ".join(f"{k}={v:.6f}" if isinstance(v, float) else f"{k}='{escape(str(v))}'" for k, v in example_details.items())
        write_html(f"<tr><td><code>{escape(err_type)}</code></td><td>{details['count']}</td><td>{details_str}</td><td>{details.get('first_ts', 0):.6f}</td></tr>")
    write_html("</tbody></table></details>")
def _write_parity_errors(write_html, parity_errors):
    write_html("<details close><summary>LIN PID Parity Errors</summary><table>")
    write_html("<thead><tr><th>Received PID</th><th>Expected PID</th><th>Occurrences</th><th>First Timestamp (s)</th></tr></thead><tbody>")
    for pid, details in sorted(parity_errors.items()):
        raw_id = pid & 0x3F
        p0 = ((raw_id >> 0) ^ (raw_id >> 1) ^ (raw_id >> 2) ^ (raw_id >> 4)) & 1
        p1 = (~((raw_id >> 1) ^ (raw_id >> 3) ^ (raw_id >> 4) ^ (raw_id >> 5))) & 1
        expected_pid = raw_id | (p0 << 6) | (p1 << 7)
        write_html(f"<tr><td><code>0x{pid:02X}</code></td><td><code>0x{expected_pid:02X}</code></td><td>{details['count']}</td><td>{details.get('first_ts', 0):.6f}</td></tr>")
    write_html("</tbody></table></details>")
def _write_dlc_errors(write_html, dlc_errors, ldf_data):
    write_html("<details close><summary>LIN DLC Errors</summary><table>")
    write_html("<thead><tr><th>ID</th><th>Frame Name</th><th>Expected</th><th>Observed</th><th>Count</th><th>First Seen (s)</th></tr></thead><tbody>")
    for (fid, exp, obs), details in sorted(dlc_errors.items()):
        frame_name = next((f.name for f in ldf_data.frames.values() if f.id == fid), 'Unknown')
        write_html(f"<tr><td><code>0x{fid:02X}</code></td><td><code>{escape(frame_name)}</code></td><td>{exp}</td><td>{obs}</td><td>{details['count']}</td><td>{details.get('first_ts', 0):.6f}</td></tr>")
    write_html("</tbody></table></details>")
def _write_checksum_errors(write_html, checksum_errors, ldf_data):
    write_html("<details close><summary>LIN Checksum Errors</summary><table>")
    write_html("<thead><tr><th>ID</th><th>Frame Name</th><th>Expected</th><th>Observed</th><th>Count</th><th>First Seen (s)</th></tr></thead><tbody>")
    for (fid, exp, obs), details in sorted(checksum_errors.items()):
        frame_name = next((f.name for f in ldf_data.frames.values() if f.id == fid), 'Unknown')
        write_html(f"<tr><td><code>0x{fid:02X}</code></td><td><code>{escape(frame_name)}</code></td><td><code>0x{exp:02X}</code></td><td><code>0x{obs:02X}</code></td><td>{details['count']}</td><td>{details.get('first_ts', 0):.6f}</td></tr>")
    write_html("</tbody></table></details>")
def _generate_gateway_mismatch_table_html(mismatched_pairs, max_mismatches_to_show=10):
    if not mismatched_pairs: return "<p><em>No value mismatches recorded for correlated pairs.</em></p>"
    html_parts = ["<p><strong>Example Value Mismatches:</strong></p>"]
    html_parts.append("<table><thead><tr>")
    for prefix in ["Src.", "Tgt."]:
        html_parts.append(f"<th>{prefix} TS (s)</th>")
        html_parts.append(f"<th>{prefix} Raw</th>")
        html_parts.append(f"<th>{prefix} Phys.</th>")
        html_parts.append(f"<th>{prefix} Logical</th>")
    html_parts.append("<th>Latency (ms)</th></tr></thead><tbody>")
    for i, pair in enumerate(mismatched_pairs):
        if i >= max_mismatches_to_show: break
        html_parts.append("<tr>")
        html_parts.append(f"<td>{pair['ts_source']:.6f}</td>")
        html_parts.append(f"<td><code>0x{pair['raw_source']:X}</code></td>")
        html_parts.append(f"<td><code>{pair['phys_source']:.6g}</code></td>")
        html_parts.append(f"<td><code>{escape(str(pair['logical_source']))}</code></td>")
        html_parts.append(f"<td>{pair['ts_target']:.6f}</td>")
        html_parts.append(f"<td><code>0x{pair['raw_target']:X}</code></td>")
        html_parts.append(f"<td><code>{pair['phys_target']:.6g}</code></td>")
        html_parts.append(f"<td><code>{escape(str(pair['logical_target']))}</code></td>")
        html_parts.append(f"<td>{pair['latency_ms']:.3f}</td>")
        html_parts.append("</tr>")
    html_parts.append("</tbody></table>")
    if len(mismatched_pairs) > max_mismatches_to_show:
        html_parts.append(f"<p style='font-size:0.8em; color:grey;'>Displaying first {max_mismatches_to_show} of {len(mismatched_pairs)} mismatches.</p>")
    return "".join(html_parts)
def _write_gateway_view_section(write_html, log_stats):
    write_html("<h2>Gateway Analysis</h2>")
    gw_res = log_stats.get('gateway_results', {})
    if not gw_res:
        write_html("<p><i>Gateway Analysis was enabled, but no gateway data was processed. Check map file and log content.</i></p>")
        return
    write_html("<details close><summary>Gateway Latency & Correlation Overview</summary><table>")
    write_html("<thead><tr><th>Mapping</th><th>Source Events</th><th>Correlated Pairs</th><th>Uncorrelated (Lost)</th><th>Avg Latency (ms)</th><th>Min (ms)</th><th>Max (ms)</th></tr></thead><tbody>")
    sorted_results = sorted(gw_res.items(), key=lambda item: f"{item[1].get('mapping_info', {}).get('source_signal', '')}")
    for idx, res in sorted_results:
        mi = res.get('mapping_info', {})
        map_label = f"<code>[{mi.get('source_network', '')}].{mi.get('source_signal', '')} → [{mi.get('target_network', '')}].{mi.get('target_signal', '')}</code>"
        ls = res.get('latency_stats', {})
        correlated_count = ls.get('count', 0)
        total_comparisons = res.get('comparisons', 0)
        lost_count = total_comparisons - correlated_count
        lost_tag = tag('KO', lost_count) if lost_count > 0 else str(lost_count)
        avg_latency_s = ls.get('average')
        avg_ms_str = f"{avg_latency_s * 1000:.3f}" if avg_latency_s is not None else "-"
        min_ms_str = f"{ls.get('min', 0) * 1000:.3f}" if ls.get('min') != float('inf') else "-"
        max_ms_str = f"{ls.get('max', 0) * 1000:.3f}" if ls.get('max') != float('-inf') else "-"
        write_html(f"<tr><td>{map_label}</td><td>{total_comparisons}</td><td>{correlated_count}</td><td>{lost_tag}</td><td>{avg_ms_str}</td><td>{min_ms_str}</td><td>{max_ms_str}</td></tr>")
    write_html("</tbody></table></details>")
    mappings_with_mismatches = sorted([(idx, res) for idx, res in gw_res.items() if res.get('mismatches_value', 0) + res.get('mismatches_type', 0) > 0], key=lambda item: f"{item[1].get('mapping_info', {}).get('source_signal', '')}")
    if mappings_with_mismatches:
        write_html("<details close><summary>Gateway Value Mismatches</summary>")
        for idx, res in mappings_with_mismatches:
            mi = res.get('mapping_info', {})
            map_label = f"<code>[{mi.get('source_network')}].{mi.get('source_signal')} → [{mi.get('target_network')}].{mi.get('target_signal')}</code>"
            mismatch_count = res.get('mismatches_value', 0) + res.get('mismatches_type', 0)
            write_html(f"<h4>Mapping: {map_label} ({mismatch_count} mismatches)</h4>")     
            mismatch_examples = res.get('mismatch_examples', [])
            if mismatch_examples:
                write_html(_generate_gateway_mismatch_table_html(mismatch_examples))
        write_html("</details>")
def generate_html_report(log_stats, args, ldf_data: LDFData, log_path, ldf_path,
                         dbc_paths: Dict[str, Union[str, List[str]]],
                         can_dbcs: Dict[str, Dict[int, DBCMessage]],
                         user_gateway_map: Optional[List[Dict[str, Any]]]):
    output_file_path = log_stats['config_used'].get('output_file')
    if output_file_path:
        report_filename = output_file_path
    else:
        report_filename = f"LR_{os.path.splitext(os.path.basename(log_path))[0]}.html"
    try:
        with open(report_filename, 'w', encoding='utf-8') as f_report:
            def write_html(html_content):
                f_report.write(html_content + "\n")
            _write_report_header(write_html, log_stats)
            _write_summary_tables(write_html, log_stats, args, can_dbcs, ldf_data)
            _write_statistics_section(write_html, log_stats, ldf_data)
            _write_logger_activity_section(write_html, log_stats)
            _write_error_details_section(write_html, log_stats, ldf_data)
            _write_slave_fault_details(write_html, log_stats)
            _write_schedule_adherence_section(write_html, log_stats, ldf_data)
            _write_node_performance_section(write_html, log_stats)
            _write_slave_reliability_section(write_html, log_stats)
            _write_schedule_jitter_section(write_html, log_stats, ldf_data)
            _write_physical_metrics_table(write_html, log_stats)
            if log_stats.get('config_used', {}).get('enable_gateway_validation'):
                _write_gateway_view_section(write_html, log_stats)
            write_html("</body></html>")
        print(f"LINSpector report generated: {report_filename}")
        return report_filename
    except (IOError, FileNotFoundError) as e:
        print(f"Failed to write Linspector report to '{report_filename}'. Please ensure the directory exists and you have write permissions. Error: {e}")
        return None
def main():
    parser = argparse.ArgumentParser(
        description=f"{SCRIPT_NAME} v{SCRIPT_VERSION} - Analyze LIN/CAN logs based on LDF/DBC definitions.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--config', type=str, help="Path to a JSON configuration file. CLI arguments override file values.")
    parser.add_argument('--ldf', help='Path to the LIN Description File (LDF).')
    parser.add_argument('--log', help='Path to the log file to analyze.')
    parser.add_argument('--gm', '--gateway_map', dest='gateway_map_file', type=str, help='Path to the JSON file with gateway signal mappings.')
    parser.add_argument('--can1_dbc', nargs='+', help='Path(s) to the DBC file(s) for CAN1.')
    parser.add_argument('--can2_dbc', nargs='+', help='Path(s) to the DBC file(s) for CAN2.')
    parser.add_argument('--can3_dbc', nargs='+', help='Path(s) to the DBC file(s) for CAN3.')
    parser.add_argument('--canfd1_dbc', nargs='+', help='Path(s) to the DBC file(s) for CANFD1.')
    parser.add_argument('--canfd2_dbc', nargs='+', help='Path(s) to the DBC file(s) for CANFD2.')
    parser.add_argument('--canfd3_dbc', nargs='+', help='Path(s) to the DBC file(s) for CANFD3.')
    parser.add_argument('--gateway_tolerance', type=float, default=DEFAULT_GATEWAY_TOLERANCE_S, help='Time tolerance (seconds) for gateway matching.')
    parser.add_argument('--exclude_gateway_signals', type=str, help='Comma-separated SOURCE signal names to exclude from gateway comparison.')
    parser.add_argument('--lin_baudrate', type=int, default=DEFAULT_LIN_BAUDRATE, help='LIN bus baud rate in bps.')
    parser.add_argument('--bus_load_window_s', type=float, default=DEFAULT_BUS_LOAD_WINDOW_S, help='Window size in seconds for bus load calculation.')
    parser.add_argument('--summary-limit', type=int, default=DEFAULT_SUMMARY_LIMIT, help='Maximum number of examples to show in summaries.')
    parser.add_argument('--disable_checksum', action='store_true', help='Disable LIN checksum validation.')
    parser.add_argument('--disable_physical', action='store_true', help='Disable LIN physical layer validation.')
    parser.add_argument('--disable_schedule', action='store_true', help='Disable LIN schedule validation.')
    parser.add_argument('--disable_gateway', action='store_true', help='Disable all gateway validation.')
    args = parser.parse_args()
    if args.config:
        if not os.path.isfile(args.config):
            print(f"ERROR: Configuration file not found: {args.config}")
            sys.exit(1)
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
            parser.set_defaults(**config_data)
        except json.JSONDecodeError as e:
            print(f"ERROR: Syntax error in JSON configuration file: {e}")
            sys.exit(1)
    args = parser.parse_args()
    if not args.log:
        parser.error("The --log argument is required (either via CLI or configuration file).")
    if not args.ldf:
        parser.error("The --ldf argument is required (either via CLI or configuration file).")
    if not os.path.isfile(args.log):
        print(f"ERROR: Log file not found: {args.log}")
        sys.exit(1)
    if not os.path.isfile(args.ldf):
        print(f"ERROR: LDF file not found: {args.ldf}")
        sys.exit(1)
    try:
        ldf_data = parse_ldf(args.ldf)
        if ldf_data and ldf_data.schedules:
            original_schedules = ldf_data.schedules.copy()
            unique_schedules, orig_to_rep, rep_to_grouped = group_equivalent_schedules(original_schedules)
            ldf_data.schedules = unique_schedules
            schedule_maps = {'orig_to_rep': orig_to_rep, 'rep_to_grouped': rep_to_grouped}
        else:
            schedule_maps = {}
    except Exception as e:
        print(f"ERROR: Failed to parse LDF file '{args.ldf}': {e}")
        sys.exit(1)
    can_dbcs_loaded = {}
    dbc_paths_for_report = {}
    dbc_channel_args = {
        'CAN1': args.can1_dbc, 'CAN2': args.can2_dbc, 'CAN3': args.can3_dbc,
        'CANFD1': args.canfd1_dbc, 'CANFD2': args.canfd2_dbc, 'CANFD3': args.canfd3_dbc
    }
    any_dbc_provided = any(v for v in dbc_channel_args.values())
    for channel_name, dbc_paths in dbc_channel_args.items():
        if dbc_paths:
            for path in dbc_paths:
                if not os.path.isfile(path):
                    print(f"ERROR: DBC file not found: {path}")
                    sys.exit(1)
            try:
                messages, _ = parse_dbcs_for_channel(dbc_paths)
                if messages:
                    can_dbcs_loaded[channel_name] = messages
                    dbc_paths_for_report[channel_name] = dbc_paths
            except Exception as e:
                print(f"ERROR: Failed to parse DBC files for {channel_name}: {e}")
                sys.exit(1)
    enable_gateway_validation = not args.disable_gateway and args.gateway_map_file and any_dbc_provided
    user_gateway_map = None
    gateway_lookup_for_processing = {}
    gateway_map_warnings = []
    
    if enable_gateway_validation:
        user_gateway_map = load_gateway_map(args.gateway_map_file)
        if user_gateway_map:
            gateway_lookup = {'source': defaultdict(lambda: defaultdict(list)), 'target': defaultdict(lambda: defaultdict(list))}
            ldf_sigs_by_name = {s.name: s for f in ldf_data.frames.values() for s in f.signals}
            dbc_sigs_by_name = {sig.name: sig for dbc in can_dbcs_loaded.values() for msg in dbc.values() for sig in msg.signals}

            for map_index, mapping in enumerate(user_gateway_map):
                mapping['map_index'] = map_index
                
                src_details = find_message_details_for_gateway(mapping['source_network'], mapping['source_message'], mapping['source_signal'], ldf_data, can_dbcs_loaded, gateway_map_warnings, map_index, 'source')
                tgt_details = find_message_details_for_gateway(mapping['target_network'], mapping['target_message'], mapping['target_signal'], ldf_data, can_dbcs_loaded, gateway_map_warnings, map_index, 'target')

                if src_details:
                    if mapping['source_network'] == 'LIN':
                        mapping['_source_signal_obj'] = ldf_sigs_by_name.get(mapping['source_signal'])
                    else:
                        mapping['_source_signal_obj'] = dbc_sigs_by_name.get(mapping['source_signal'])
                    if mapping.get('_source_signal_obj'):
                         gateway_lookup['source'][mapping['source_network']][src_details[0]].append(mapping)

                if tgt_details:
                    if mapping['target_network'] == 'LIN':
                        mapping['_target_signal_obj'] = ldf_sigs_by_name.get(mapping['target_signal'])
                    else:
                        mapping['_target_signal_obj'] = dbc_sigs_by_name.get(mapping['target_signal'])
                    if mapping.get('_target_signal_obj'):
                        gateway_lookup['target'][mapping['target_network']][tgt_details[0]].append(mapping)

            gateway_lookup_for_processing = gateway_lookup
        else:
            enable_gateway_validation = False
            
    enable_schedule_validation = not args.disable_schedule and bool(ldf_data.schedules)
    config = {
        "ldf_file": args.ldf,
        "log_file": args.log,
        "gateway_map_file": args.gateway_map_file,
        "gateway_tolerance": args.gateway_tolerance,
        "lin_baudrate": args.lin_baudrate,
        "bus_load_window_s": args.bus_load_window_s,
        "exclude_gateway_signals": set(s.strip() for s in args.exclude_gateway_signals.split(',')) if args.exclude_gateway_signals else set(),
        "schedule_tolerance_factor": 0.1,
        "schedule_min_tolerance_s": DEFAULT_SCHEDULE_MIN_ABSOLUTE_TOLERANCE_S,
        "schedule_maps": schedule_maps,
        "summary_limit": args.summary_limit,
        "enable_checksum_validation": not args.disable_checksum,
        "enable_physical_validation": not args.disable_physical,
        "enable_schedule_validation": enable_schedule_validation,
        "enable_gateway_validation": enable_gateway_validation,
    }
    log_stats = process_log_file(
        log_path=args.log,
        ldf_data=ldf_data,
        can_dbcs=can_dbcs_loaded,
        gateway_lookup=gateway_lookup_for_processing,
        config=config,
        progress_callback=None
    )
    log_stats['gateway_map_warnings'] = gateway_map_warnings
    log_stats['ldf_data_for_report'] = ldf_data
    config['dbc_files'] = dbc_paths_for_report
    class ArgsForReport:
        def __init__(self, config_dict):
            self.gm = config_dict.get('gateway_map_file')
            self.enable_physical_validation = config_dict.get('enable_physical_validation', True)
            self.enable_checksum_validation = config_dict.get('enable_checksum_validation', True)
            self.enable_schedule_validation = config_dict.get('enable_schedule_validation', True)
            self.gateway_map_warnings_runtime = log_stats.get('gateway_map_warnings', [])
            self.dbc_files = config_dict.get('dbc_files', {})
    args_for_report = ArgsForReport(config)
    generate_html_report(
        log_stats=log_stats,
        args=args_for_report,
        ldf_data=ldf_data,
        log_path=config['log_file'],
        ldf_path=config['ldf_file'],
        dbc_paths=config['dbc_files'],
        can_dbcs=can_dbcs_loaded,
        user_gateway_map=user_gateway_map
    )
if __name__ == "__main__":
    main()
