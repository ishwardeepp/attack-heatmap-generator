# MITRE ATT&CK Heatmap Generator - Professional Edition

A comprehensive, production-ready Python tool for generating MITRE ATT&CK heatmaps from various input sources. Built for threat intelligence research with extensive validation, logging, and testing.

## 🌟 Key Features

### Core Capabilities
- **Multiple Input Formats**: Keyword search, JSON, CSV, STIX bundles, text extraction
- **Advanced Scoring**: Linear, logarithmic, weighted, and normalized algorithms
- **Multi-Matrix Support**: Enterprise, Mobile, and ICS ATT&CK matrices
- **Platform Filtering**: Filter techniques by platform (Windows, Linux, macOS, etc.)
- **Threshold Control**: Focus on high-frequency techniques

### Professional Features
- **Comprehensive Validation**: Input validation with detailed error messages
- **Structured Logging**: Context-aware logging with metrics tracking
- **Smart Caching**: Automatic caching of ATT&CK data with TTL
- **Error Resilience**: Retry logic for network operations
- **Extensive Testing**: 50+ test cases covering all functionality

### Developer-Friendly
- **Type Hints**: Full type annotations throughout
- **Modular Design**: Clean separation of concerns
- **Well-Documented**: Comprehensive docstrings and comments
- **Test Coverage**: Unit tests for all major components

## 📋 Requirements

- Python 3.9 or higher
- Internet connection (for downloading ATT&CK data)

## 🚀 Installation

```bash
# Clone the repository
git clone <repository-url>
cd mitre-attack-heatmap-pro

# Install dependencies
pip install -r requirements.txt
```

## 💻 Usage

### Basic Examples

#### 1. Generate from Threat Group Keywords

```bash
# Energy sector threats
python heatmap_gen.py groups -s energy -o energy_heatmap -t "Energy Sector Threats"

# Multiple keywords
python heatmap_gen.py groups -s financial banking -o financial_threats -t "Financial Threats"

# All threat groups
python heatmap_gen.py groups -s "*" -o all_groups -t "All Known Threat Groups"
```

#### 2. Generate from Technique List File

```bash
# From JSON file
python heatmap_gen.py techniques -i techniques.json -o my_analysis -t "My Analysis"

# From CSV file
python heatmap_gen.py techniques -i report.csv -o csv_analysis -t "CSV Analysis"

# From STIX bundle
python heatmap_gen.py techniques -i bundle.json --format stix -o stix_analysis -t "STIX Analysis"
```

#### 3. Extract from Text

```bash
# Extract techniques from threat report
python heatmap_gen.py text -i threat_report.txt -o extracted -t "Extracted TTPs"
```

### Advanced Options

#### Scoring Algorithms

```bash
# Logarithmic scoring (reduces impact of high counts)
python heatmap_gen.py groups -s energy --scoring logarithmic -o energy_log -t "Energy (Log)"

# Normalized scoring (0-100 scale)
python heatmap_gen.py groups -s healthcare --scoring normalized -o healthcare_norm -t "Healthcare (Normalized)"
```

#### Platform Filtering

```bash
# Windows-only techniques
python heatmap_gen.py groups -s apt --platforms windows -o apt_windows -t "APT Windows Techniques"

# Multi-platform
python heatmap_gen.py groups -s ransomware --platforms windows linux -o ransomware_multi -t "Ransomware (Win/Linux)"
```

#### Threshold Filtering

```bash
# Show only techniques used by 5+ groups
python heatmap_gen.py groups -s "*" --threshold 5 -o common_ttps -t "Common Techniques (5+)"
```

#### Matrix Selection

```bash
# Mobile matrix
python heatmap_gen.py groups -s mobile --matrix mobile -o mobile_threats -t "Mobile Threats"

# ICS matrix
python heatmap_gen.py groups -s ics scada --matrix ics -o ics_threats -t "ICS/SCADA Threats"
```

#### Logging and Debugging

```bash
# Debug logging
python heatmap_gen.py groups -s test --log-level DEBUG -o debug_test -t "Debug Test"

# Log to file
python heatmap_gen.py groups -s energy --log-file energy.log -o energy -t "Energy"

# Export statistics
python heatmap_gen.py groups -s apt --export-stats -o apt_analysis -t "APT Analysis"
```

## 📊 Input File Formats

### JSON Format

#### Simple List
```json
["T1059", "T1003", "T1055.001"]
```

#### Navigator Format
```json
{
  "name": "My Layer",
  "techniques": [
    {"techniqueID": "T1059", "score": 5},
    {"techniqueID": "T1003", "score": 3}
  ]
}
```

#### Custom Format
```json
{
  "ttps": ["T1059", "T1003"],
  "metadata": {"source": "analysis"}
}
```

### CSV Format

```csv
technique_id,name,tactic
T1059,Command and Scripting Interpreter,Execution
T1003,OS Credential Dumping,Credential Access
T1055,Process Injection,Defense Evasion
```

### STIX Bundle

```json
{
  "type": "bundle",
  "objects": [
    {
      "type": "attack-pattern",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T1059.001"}
      ]
    }
  ]
}
```

### Text Extraction

Any text file containing technique IDs:
```
The threat actor used T1059.001 (PowerShell) for initial 
execution. They then performed credential dumping using 
T1003.001 and process injection (T1055) for persistence.
```

## 🧪 Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src/mitre_heatmap --cov-report=html

# Run specific test file
python -m pytest tests/test_core.py -v

# Run specific test
python -m pytest tests/test_parsers.py::TestJSONFileParser::test_parse_navigator_format -v
```

## 📁 Project Structure

```
mitre-attack-heatmap-pro/
├── src/mitre_heatmap/
│   ├── config.py          # Configuration classes and constants
│   ├── logger.py          # Structured logging
│   ├── validator.py       # Input validation
│   ├── data_handler.py    # ATT&CK data management
│   ├── parsers.py         # Input format parsers
│   └── generator.py       # Core heatmap generation
├── tests/
│   ├── test_core.py       # Core functionality tests
│   └── test_parsers.py    # Parser tests
├── config/                # Configuration files
├── examples/              # Example input files
├── output/                # Generated heatmaps
├── heatmap_gen.py        # Main CLI application
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🔧 Configuration

The tool uses a comprehensive configuration system. Key settings:

```python
# Matrix type
matrix_type = MatrixType.ENTERPRISE  # or MOBILE, ICS

# Scoring algorithm
scoring_algorithm = ScoringAlgorithm.LINEAR  # or LOGARITHMIC, WEIGHTED, NORMALIZED

# Color scheme
color_scheme = ColorScheme.RED_YELLOW_GREEN  # or BLUE_WHITE_RED, VIRIDIS, PLASMA

# Filtering
threshold = 0  # Minimum score for parent techniques
merge_subtechniques = True  # Propagate sub-technique scores
platforms = ["windows", "linux"]  # Platform filter

# Caching
cache.enabled = True
cache.ttl_hours = 24

# Logging
logging.level = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
```

## 📊 Understanding the Output

### Navigator Layer JSON

The tool generates a JSON file compatible with [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):

- **Red cells**: Lower scores (fewer groups/occurrences)
- **Yellow cells**: Medium scores
- **Green cells**: Higher scores (many groups/occurrences)

### Statistics File

With `--export-stats`, you get a JSON file with:
- Total techniques count
- Score statistics (min, max, mean, median)
- Parent vs sub-technique breakdown
- Metadata about the generation

## 🎯 Use Cases

### Threat Intelligence Research
- Analyze threat actor TTPs by industry
- Identify common attack patterns
- Track technique evolution over time

### Purple Team Exercises
- Prioritize techniques for testing
- Create scenario-based heatmaps
- Map coverage gaps

### Detection Engineering
- Identify high-priority techniques
- Assess detection coverage
- Focus on industry-specific threats

### Security Assessments
- Visualize attack surface
- Compare threat landscapes
- Generate executive reports

## 🔍 Logging and Debugging

The tool provides comprehensive logging:

### Log Levels
- **DEBUG**: Detailed execution flow
- **INFO**: Key operations and results
- **WARNING**: Non-critical issues
- **ERROR**: Operation failures
- **CRITICAL**: Fatal errors

### Logged Information
- Configuration validation results
- Data download/cache operations
- Technique extraction and filtering
- Score calculations
- Operation timing metrics

### Example Log Output
```
2024-02-16 10:30:00 - mitre_heatmap - INFO - Starting operation: load_attack_data
2024-02-16 10:30:01 - mitre_heatmap - INFO - Using cached ATT&CK data
2024-02-16 10:30:01 - mitre_heatmap - INFO - Loaded 658 techniques, 142 groups, 23451 relationships
2024-02-16 10:30:02 - mitre_heatmap - INFO - Found 15 matching groups: APT28, APT29, ...
2024-02-16 10:30:02 - mitre_heatmap - INFO - Threshold filter: 245 -> 127 techniques
```

## 🧩 Extending the Tool

### Adding New Scoring Algorithms

Edit `src/mitre_heatmap/generator.py`:

```python
def _custom_score(self, technique_counts: Dict[str, int]) -> Dict[str, float]:
    """Your custom scoring logic."""
    return {tech: your_calculation(count) for tech, count in technique_counts.items()}
```

### Adding New Input Parsers

Create a new parser in `src/mitre_heatmap/parsers.py`:

```python
class CustomParser(InputParser):
    def parse(self, input_data: Any) -> ValidationResult:
        # Your parsing logic
        return ValidationResult(True, [], [], sanitized_value=techniques)
```

### Adding New Export Formats

Future versions will support HTML, SVG, PNG, PDF exports. Framework is in place in `config.py`.

## 🐛 Troubleshooting

### Common Issues

**"Failed to download ATT&CK data"**
- Check internet connection
- Verify firewall settings
- Try with `--no-cache` flag

**"No matching groups found"**
- Check spelling of search terms
- Try broader keywords
- Use `--log-level DEBUG` to see search details

**"Validation failed"**
- Check input file format
- Verify technique ID format (T#### or T####.###)
- Use `--log-level DEBUG` for details

### Getting Help

1. Enable debug logging: `--log-level DEBUG`
2. Check log file with `--log-file debug.log`
3. Run tests: `python -m pytest tests/ -v`
4. Review error messages - they're designed to be helpful!

## 📝 Examples

See the `examples/` directory for:
- Sample JSON files
- Sample CSV files
- Sample STIX bundles
- Example text reports
- Common use case configurations

## 🤝 Contributing

Contributions welcome! The codebase is designed for extensibility:

- Add new parsers for different input formats
- Implement new scoring algorithms
- Add new export formats
- Enhance filtering capabilities
- Improve test coverage


## 🙏 Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) - The threat intelligence framework
- [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) - Visualization tool
- [MITRE ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data) - Machine-readable data

---

**Built for threat intelligence professionals who demand reliability, flexibility, and comprehensive validation.**
