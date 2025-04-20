# WAF Module Initialization
from .waf_core import WAFCore
from .waf_utils import create_database, get_db_connection, format_log_entry, get_attack_color, truncate_string

__all__ = [
    'WAFCore',
    'create_database',
    'get_db_connection',
    'format_log_entry',
    'get_attack_color',
    'truncate_string'
]
