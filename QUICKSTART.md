# Quick Start Guide

## Installation (30 seconds)

```bash
cd mitre-attack-heatmap-pro
pip install -r requirements.txt
```

## Your First Heatmap (1 minute)

### Option 1: From Threat Group Search
```bash
python heatmap_gen.py groups -s energy -o my_first_heatmap -t "Energy Sector Threats"
```

### Option 2: From Example File
```bash
python heatmap_gen.py techniques -i examples/sample_techniques.json -o example_heatmap -t "Example Analysis"
```

### Option 3: Extract from Text
```bash
python heatmap_gen.py text -i examples/threat_report.txt -o extracted_heatmap -t "Extracted TTPs"
```

## View Your Heatmap

1. Open [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click "Open Existing Layer" → "Upload from local"
3. Select your `output/my_first_heatmap.json` file

## Run Tests

```bash
# Quick test
python run_tests.py

# With coverage report
python run_tests.py coverage
```

## Common Commands

```bash
# All threat groups, show only common techniques
python heatmap_gen.py groups -s "*" --threshold 5 -o common -t "Common Techniques"

# Healthcare sector with logarithmic scoring
python heatmap_gen.py groups -s healthcare medical --scoring logarithmic -o healthcare -t "Healthcare Threats"

# Windows-only techniques from APT groups
python heatmap_gen.py groups -s apt --platforms windows -o apt_windows -t "APT Windows"

# Debug mode with detailed logging
python heatmap_gen.py groups -s test --log-level DEBUG -o debug_test -t "Debug Test"

# Export statistics
python heatmap_gen.py groups -s ransomware --export-stats -o ransomware -t "Ransomware Analysis"
```

## Need Help?

```bash
# General help
python heatmap_gen.py --help

# Command-specific help
python heatmap_gen.py groups --help
python heatmap_gen.py techniques --help
python heatmap_gen.py text --help
```

## Troubleshooting

**No internet connection?**
- The tool downloads ATT&CK data on first run (~25MB)
- Subsequent runs use cached data

**Tests failing?**
- Make sure you installed dependencies: `pip install -r requirements.txt`
- Check Python version: `python --version` (need 3.9+)

**Want detailed logs?**
- Add `--log-level DEBUG` to any command
- Save logs: `--log-file my_run.log`

## What's Next?

- Read the full [README.md](README.md) for advanced features
- Check out [examples/](examples/) for sample input files
- Explore different scoring algorithms and filters
- Run the comprehensive test suite

## Pro Tips

1. **Use caching**: First run downloads data, subsequent runs are instant
2. **Try thresholds**: Use `--threshold 5` to focus on common techniques
3. **Platform filtering**: Focus analysis with `--platforms windows linux`
4. **Export stats**: Add `--export-stats` for detailed metrics
5. **Wildcard search**: Use `-s "*"` to include all threat groups

Happy heatmapping! 🔥
