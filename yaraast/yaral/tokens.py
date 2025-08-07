"""YARA-L specific token types."""

from enum import Enum, auto


class YaraLTokenType(Enum):
    """Token types specific to YARA-L."""

    # YARA-L specific sections
    EVENTS = auto()
    MATCH = auto()
    OUTCOME = auto()
    OPTIONS = auto()

    # Time-related tokens
    OVER = auto()
    BEFORE = auto()
    AFTER = auto()
    WITHIN = auto()

    # Time units
    SECONDS = auto()
    MINUTES = auto()
    HOURS = auto()
    DAYS = auto()

    # Aggregation functions
    COUNT = auto()
    COUNT_DISTINCT = auto()
    SUM = auto()
    MIN = auto()
    MAX = auto()
    AVG = auto()
    ARRAY = auto()
    ARRAY_DISTINCT = auto()
    EARLIEST = auto()
    LATEST = auto()

    # UDM fields prefixes
    METADATA = auto()
    PRINCIPAL = auto()
    TARGET = auto()
    NETWORK = auto()
    SECURITY_RESULT = auto()
    UDM = auto()
    ADDITIONAL = auto()

    # YARA-L operators
    CIDR = auto()
    REGEX = auto()
    IS = auto()
    NULL = auto()

    # Reference lists
    REFERENCE_LIST = auto()  # %list_name%

    # Event variables
    EVENT_VAR = auto()  # $e, $e1, $e2, etc.

    # Field placeholders
    PLACEHOLDER = auto()  # %field%

    # Special
    NOCASE = auto()
    IF = auto()
    ELSE = auto()
    BY = auto()
    EVERY = auto()

    # Symbols specific to YARA-L
    ARROW = auto()  # ->
    DOUBLE_COLON = auto()  # ::

    # Literal types
    TIME_LITERAL = auto()  # 5m, 1h, 7d

    # EOF
    EOF = auto()
