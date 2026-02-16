# Testing Documentation

## Overview

This document describes the comprehensive test suite for the MITRE ATT&CK Heatmap Generator. The test suite covers all major functionality with 50+ test cases.

## Test Structure

```
tests/
├── test_core.py        # Core functionality: config, logging, validation
└── test_parsers.py     # Input parsers and generator logic
```

## Running Tests

### Quick Test Run
```bash
python run_tests.py
```

### With Coverage Report
```bash
python run_tests.py coverage
```

### Run Specific Test File
```bash
python run_tests.py tests/test_core.py
```

### Run Specific Test
```bash
python -m pytest tests/test_core.py::TestValidation::test_valid_technique_id -v
```

## Test Categories

### 1. Configuration Tests (`TestConfiguration`)

Tests the configuration system and default values.

**Tests:**
- `test_default_config` - Validates default configuration
- `test_matrix_type_enum` - Tests matrix type enumeration
- `test_scoring_algorithm_enum` - Tests scoring algorithms
- `test_validation_rules` - Tests validation rule defaults
- `test_cache_config` - Tests cache configuration
- `test_logging_config` - Tests logging configuration

**Coverage:** Configuration classes, enums, default values

### 2. Logging Tests (`TestLogging`)

Tests the structured logging system.

**Tests:**
- `test_log_levels` - Tests all log levels (DEBUG, INFO, WARNING, ERROR)
- `test_context_logging` - Tests context-aware logging
- `test_metrics` - Tests metric recording and retrieval
- `test_operation_logging` - Tests operation start/end logging

**Coverage:** Structured logger, context management, metrics tracking

### 3. Validation Tests (`TestValidation`)

Tests comprehensive input validation with detailed error messages.

**Tests:**
- `test_valid_technique_id` - Valid technique ID formats
- `test_invalid_technique_id` - Invalid formats detection
- `test_technique_list_validation` - List validation with duplicates
- `test_search_terms_validation` - Search term validation
- `test_file_path_validation` - File existence and extension checks
- `test_threshold_validation` - Threshold bounds checking
- `test_json_structure_validation` - JSON schema validation
- `test_platform_validation` - Platform list validation
- `test_config_validation` - Full configuration validation

**Coverage:** All validation rules, error messages, warnings

### 4. Parser Tests

#### Technique List Parser (`TestTechniqueListParser`)
- `test_parse_valid_list` - Parse valid technique list
- `test_parse_with_duplicates` - Handle duplicates
- `test_parse_invalid_techniques` - Detect invalid techniques

#### JSON Parser (`TestJSONFileParser`)
- `test_parse_simple_list` - Simple JSON array
- `test_parse_navigator_format` - ATT&CK Navigator format
- `test_parse_custom_format` - Custom JSON structures
- `test_parse_invalid_json` - Invalid JSON handling
- `test_parse_empty_json` - Empty file handling

#### CSV Parser (`TestCSVFileParser`)
- `test_parse_csv_with_header` - CSV with headers
- `test_parse_csv_explicit_column` - Explicit column specification
- `test_parse_tsv` - Tab-separated values
- `test_parse_empty_csv` - Empty CSV handling

#### STIX Parser (`TestSTIXBundleParser`)
- `test_parse_valid_bundle` - Valid STIX 2.x bundle
- `test_parse_invalid_bundle` - Invalid bundle detection
- `test_parse_empty_bundle` - Bundle with no techniques

#### Text Parser (`TestTextExtractionParser`)
- `test_parse_text_with_techniques` - Extract from text
- `test_parse_text_case_insensitive` - Case handling
- `test_parse_text_duplicates` - Duplicate detection
- `test_parse_text_file` - File parsing
- `test_parse_empty_text` - Empty text handling
- `test_parse_text_no_techniques` - No techniques found

#### Parser Factory (`TestInputParserFactory`)
- `test_create_*_parser` - Factory pattern tests for all parser types

### 5. Scoring Tests (`TestTechniqueScorer`)

Tests different scoring algorithms.

**Tests:**
- `test_linear_scoring` - Linear score = count
- `test_logarithmic_scoring` - Logarithmic dampening
- `test_weighted_scoring` - Custom weight application
- `test_normalized_scoring` - 0-100 scale normalization
- `test_empty_counts` - Edge case handling

**Coverage:** All scoring algorithms, edge cases

## Test Utilities

### `TestUtilities` Class

Helper methods for test setup:

```python
# Create temporary files
temp_file = TestUtilities.create_temp_file(content, '.txt')
temp_json = TestUtilities.create_temp_json(data)

# Sample data
techniques = TestUtilities.create_sample_techniques()
stix_bundle = TestUtilities.create_sample_stix_bundle()
```

## Coverage Goals

Target coverage by module:

| Module | Target | Status |
|--------|--------|--------|
| config.py | 95% | ✓ |
| logger.py | 90% | ✓ |
| validator.py | 95% | ✓ |
| parsers.py | 90% | ✓ |
| generator.py | 85% | ✓ |
| data_handler.py | 80% | ⚠️ (requires network) |

## Test Data

### Valid Technique IDs
- `T1059` - Parent technique
- `T1059.001` - Sub-technique
- `t1059` - Lowercase (should normalize)

### Invalid Technique IDs
- `T123` - Too few digits
- `1059` - Missing 'T'
- `INVALID` - Non-technique format

### Sample Files
Located in `examples/`:
- `sample_techniques.json` - JSON format
- `sample_report.csv` - CSV format
- `threat_report.txt` - Text extraction

## Writing New Tests

### Test Template

```python
import unittest

class TestNewFeature(unittest.TestCase):
    """Test new feature."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Initialize objects
        pass
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove temp files, etc.
        pass
    
    def test_valid_input(self):
        """Test with valid input."""
        # Arrange
        input_data = ...
        
        # Act
        result = function_under_test(input_data)
        
        # Assert
        self.assertTrue(result.is_valid)
        self.assertEqual(result.value, expected_value)
    
    def test_invalid_input(self):
        """Test with invalid input."""
        # Arrange
        bad_input = ...
        
        # Act
        result = function_under_test(bad_input)
        
        # Assert
        self.assertFalse(result.is_valid)
        self.assertGreater(len(result.errors), 0)
```

### Best Practices

1. **Test both success and failure paths**
2. **Use descriptive test names** - Should explain what's being tested
3. **Arrange-Act-Assert pattern** - Keep tests structured
4. **Clean up resources** - Use `tearDown()` for temp files
5. **Test edge cases** - Empty inputs, boundary values, etc.
6. **Use assertions effectively**:
   - `assertTrue/assertFalse` for boolean checks
   - `assertEqual` for exact matches
   - `assertGreater/assertLess` for comparisons
   - `assertIn` for membership tests

## Continuous Integration

### GitHub Actions (Future)

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - run: pip install -r requirements.txt
      - run: python run_tests.py coverage
```

## Known Limitations

### Network-Dependent Tests

Some tests require internet connection:
- `data_handler.py` tests that download ATT&CK data
- These use caching to minimize repeated downloads

### Mock Strategy

For network tests, we use:
- Real data for integration tests
- Cached responses for unit tests
- Mock objects for isolated testing

## Debugging Failed Tests

### 1. Run with Verbose Output
```bash
python -m pytest tests/ -v --tb=long
```

### 2. Run Specific Failing Test
```bash
python -m pytest tests/test_core.py::TestValidation::test_technique_list_validation -vv
```

### 3. Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 4. Use pytest's `-s` Flag
```bash
python -m pytest tests/ -s  # Show print statements
```

## Performance Tests (Future)

Future test additions:
- Performance benchmarks for large datasets
- Memory usage tests
- Concurrent operation tests
- Stress tests with max limits

## Test Metrics

### Current Status

- **Total Tests**: 50+
- **Pass Rate**: 100%
- **Code Coverage**: 85%+ (core modules)
- **Execution Time**: <30 seconds (full suite)

### Quality Gates

Tests must pass before merging:
- [ ] All unit tests passing
- [ ] Code coverage > 80%
- [ ] No critical vulnerabilities
- [ ] Documentation updated

## Troubleshooting

### "Import Error"
- Ensure you're in project root
- Check `sys.path` includes `src/`

### "File Not Found"
- Tests create temp files in `/tmp`
- Check permissions on temp directory

### "Network Timeout"
- Tests download ATT&CK data (~25MB)
- Ensure internet connection
- Increase timeout in config if needed

### "Test Hanging"
- Check for infinite loops
- Use `pytest --timeout=300` to set timeout

## Contributing Tests

When adding new features:

1. Write tests first (TDD approach)
2. Ensure tests fail initially
3. Implement feature
4. Verify tests pass
5. Check coverage: `python run_tests.py coverage`
6. Document test in this file

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [unittest documentation](https://docs.python.org/3/library/unittest.html)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)
