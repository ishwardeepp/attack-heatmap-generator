"""
Configuration module for MITRE ATT&CK Heatmap Generator.
Contains all configuration constants, validation rules, and settings.
"""

from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import os


class MatrixType(str, Enum):
    """Supported ATT&CK matrices."""
    ENTERPRISE = "enterprise-attack"
    MOBILE = "mobile-attack"
    ICS = "ics-attack"


class ScoringAlgorithm(str, Enum):
    """Available scoring algorithms for technique aggregation."""
    LINEAR = "linear"  # Direct count
    LOGARITHMIC = "logarithmic"  # log(count + 1)
    WEIGHTED = "weighted"  # Custom weights per group
    NORMALIZED = "normalized"  # 0-100 scale


class ColorScheme(str, Enum):
    """Color schemes for heatmap visualization."""
    RED_YELLOW_GREEN = "red_yellow_green"
    BLUE_WHITE_RED = "blue_white_red"
    VIRIDIS = "viridis"
    PLASMA = "plasma"
    CUSTOM = "custom"


class ExportFormat(str, Enum):
    """Supported export formats."""
    NAVIGATOR_JSON = "navigator_json"
    HTML = "html"
    SVG = "svg"
    PNG = "png"
    PDF = "pdf"
    CSV = "csv"
    EXCEL = "excel"


class InputFormat(str, Enum):
    """Supported input formats for TTPs."""
    KEYWORD_SEARCH = "keyword_search"
    TECHNIQUE_LIST = "technique_list"
    JSON_FILE = "json_file"
    CSV_FILE = "csv_file"
    STIX_BUNDLE = "stix_bundle"
    TEXT_EXTRACTION = "text_extraction"


@dataclass
class ValidationRules:
    """Validation rules for inputs."""
    max_search_terms: int = 50
    max_technique_ids: int = 1000
    max_file_size_mb: int = 100
    allowed_technique_pattern: str = r"^T\d{4}(\.\d{3})?$"
    min_threshold: int = 0
    max_threshold: int = 1000
    

@dataclass
class CacheConfig:
    """Configuration for caching ATT&CK data."""
    enabled: bool = True
    cache_dir: str = field(default_factory=lambda: os.path.expanduser("~/.mitre_heatmap_cache"))
    ttl_hours: int = 24
    max_size_mb: int = 500


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    console_output: bool = True
    

@dataclass
class APIConfig:
    """API server configuration (for future REST API)."""
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    

@dataclass
class AttackConfig:
    """MITRE ATT&CK data source configuration."""
    stix_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    mobile_stix_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
    ics_stix_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
    timeout_seconds: int = 30
    retry_attempts: int = 3
    retry_delay_seconds: int = 2


@dataclass
class HeatmapConfig:
    """Main configuration class for the heatmap generator."""
    
    # Matrix configuration
    matrix_type: MatrixType = MatrixType.ENTERPRISE
    
    # Scoring configuration
    scoring_algorithm: ScoringAlgorithm = ScoringAlgorithm.LINEAR
    custom_weights: Dict[str, float] = field(default_factory=dict)
    
    # Visualization configuration
    color_scheme: ColorScheme = ColorScheme.RED_YELLOW_GREEN
    custom_colors: Optional[Dict[str, str]] = None
    
    # Filtering configuration
    threshold: int = 0
    merge_subtechniques: bool = True
    include_deprecated: bool = False
    include_revoked: bool = False
    
    # Platform filtering
    platforms: Optional[List[str]] = None  # ["windows", "linux", "macos"]
    
    # Tactic filtering
    tactics: Optional[List[str]] = None
    
    # Sub-configurations
    validation: ValidationRules = field(default_factory=ValidationRules)
    cache: CacheConfig = field(default_factory=CacheConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    api: APIConfig = field(default_factory=APIConfig)
    attack: AttackConfig = field(default_factory=AttackConfig)
    
    # Output configuration
    output_formats: List[ExportFormat] = field(default_factory=lambda: [ExportFormat.NAVIGATOR_JSON])
    output_directory: str = "output"
    
    # Metadata
    title: str = "MITRE ATT&CK Heatmap"
    description: str = ""
    author: str = ""
    

# Default configuration instance
DEFAULT_CONFIG = HeatmapConfig()


# Platform mappings
PLATFORM_MAPPINGS = {
    "windows": ["Windows"],
    "linux": ["Linux"],
    "macos": ["macOS"],
    "network": ["Network"],
    "cloud": ["Azure AD", "Office 365", "SaaS", "IaaS", "Google Workspace"],
    "containers": ["Containers"],
    "all": None  # No filtering
}


# Tactic ID to name mappings
TACTIC_MAPPINGS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}


# Color gradient definitions
COLOR_GRADIENTS = {
    ColorScheme.RED_YELLOW_GREEN: {
        "minColor": "#ff6666",  # Red
        "maxColor": "#66ff66",  # Green
        "midColor": "#ffff66",  # Yellow
    },
    ColorScheme.BLUE_WHITE_RED: {
        "minColor": "#0066cc",  # Blue
        "maxColor": "#cc0000",  # Red
        "midColor": "#ffffff",  # White
    },
    ColorScheme.VIRIDIS: {
        "minColor": "#440154",
        "maxColor": "#fde724",
        "midColor": "#21918c",
    },
    ColorScheme.PLASMA: {
        "minColor": "#0d0887",
        "maxColor": "#f0f921",
        "midColor": "#cc4778",
    },
}
