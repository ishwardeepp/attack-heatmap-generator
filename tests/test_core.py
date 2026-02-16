"""
Comprehensive test suite for MITRE ATT&CK Heatmap Generator.
Part 1: Test utilities and configuration tests.
"""

import unittest
import tempfile
import json
import os
from pathlib import Path
from typing import List, Dict

# Import modules to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from mitre_heatmap.config import (
    HeatmapConfig,
    MatrixType,
    ScoringAlgorithm,
    ColorScheme,
    ValidationRules,
    CacheConfig,
    LoggingConfig
)
from mitre_heatmap.logger import StructuredLogger, get_logger
from mitre_heatmap.validator import Validator, ValidationResult


class TestUtilities:
    """Utilities for testing."""
    
    @staticmethod
    def create_temp_file(content: str, suffix: str = '.txt') -> str:
        """Create a temporary file with content."""
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        return path
    
    @staticmethod
    def create_temp_json(data: Dict, suffix: str = '.json') -> str:
        """Create a temporary JSON file."""
        content = json.dumps(data, indent=2)
        return TestUtilities.create_temp_file(content, suffix)
    
    @staticmethod
    def create_sample_techniques() -> List[str]:
        """Create sample technique IDs."""
        return [
            'T1059',      # Command and Scripting Interpreter
            'T1059.001',  # PowerShell
            'T1059.003',  # Windows Command Shell
            'T1003',      # OS Credential Dumping
            'T1003.001',  # LSASS Memory
            'T1055',      # Process Injection
            'T1078',      # Valid Accounts
            'T1566',      # Phishing
            'T1566.001',  # Spearphishing Attachment
        ]
    
    @staticmethod
    def create_sample_stix_bundle() -> Dict:
        """Create a sample STIX bundle."""
        return {
            "type": "bundle",
            "id": "bundle--test-001",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--001",
                    "name": "PowerShell",
                    "description": "Test technique",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1059.001"
                        }
                    ]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--002",
                    "name": "LSASS Memory",
                    "description": "Test technique",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1003.001"
                        }
                    ]
                }
            ]
        }


class TestConfiguration(unittest.TestCase):
    """Test configuration classes."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = HeatmapConfig()
        
        self.assertEqual(config.matrix_type, MatrixType.ENTERPRISE)
        self.assertEqual(config.scoring_algorithm, ScoringAlgorithm.LINEAR)
        self.assertEqual(config.color_scheme, ColorScheme.RED_YELLOW_GREEN)
        self.assertEqual(config.threshold, 0)
        self.assertTrue(config.merge_subtechniques)
        self.assertFalse(config.include_deprecated)
        self.assertFalse(config.include_revoked)
    
    def test_matrix_type_enum(self):
        """Test matrix type enumeration."""
        self.assertEqual(MatrixType.ENTERPRISE.value, "enterprise-attack")
        self.assertEqual(MatrixType.MOBILE.value, "mobile-attack")
        self.assertEqual(MatrixType.ICS.value, "ics-attack")
    
    def test_scoring_algorithm_enum(self):
        """Test scoring algorithm enumeration."""
        self.assertIn(ScoringAlgorithm.LINEAR, ScoringAlgorithm)
        self.assertIn(ScoringAlgorithm.LOGARITHMIC, ScoringAlgorithm)
        self.assertIn(ScoringAlgorithm.WEIGHTED, ScoringAlgorithm)
        self.assertIn(ScoringAlgorithm.NORMALIZED, ScoringAlgorithm)
    
    def test_validation_rules(self):
        """Test validation rules defaults."""
        rules = ValidationRules()
        
        self.assertEqual(rules.max_search_terms, 50)
        self.assertEqual(rules.max_technique_ids, 1000)
        self.assertEqual(rules.max_file_size_mb, 100)
        self.assertIsNotNone(rules.allowed_technique_pattern)
    
    def test_cache_config(self):
        """Test cache configuration."""
        cache_config = CacheConfig()
        
        self.assertTrue(cache_config.enabled)
        self.assertEqual(cache_config.ttl_hours, 24)
        self.assertIsNotNone(cache_config.cache_dir)
    
    def test_logging_config(self):
        """Test logging configuration."""
        log_config = LoggingConfig()
        
        self.assertEqual(log_config.level, "INFO")
        self.assertTrue(log_config.console_output)
        self.assertIsNotNone(log_config.format)


class TestLogging(unittest.TestCase):
    """Test logging functionality."""
    
    def setUp(self):
        """Set up test logger."""
        self.test_log_file = tempfile.mktemp(suffix='.log')
        self.logger = StructuredLogger(
            name="test_logger",
            level="DEBUG",
            log_file=self.test_log_file,
            console_output=False
        )
    
    def tearDown(self):
        """Clean up test log file."""
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)
    
    def test_log_levels(self):
        """Test different log levels."""
        self.logger.debug("Debug message")
        self.logger.info("Info message")
        self.logger.warning("Warning message")
        self.logger.error("Error message")
        
        # Check log file exists
        self.assertTrue(os.path.exists(self.test_log_file))
        
        # Read log file
        with open(self.test_log_file, 'r') as f:
            content = f.read()
        
        self.assertIn("Debug message", content)
        self.assertIn("Info message", content)
        self.assertIn("Warning message", content)
        self.assertIn("Error message", content)
    
    def test_context_logging(self):
        """Test context-aware logging."""
        self.logger.set_context(operation="test_op", user="test_user")
        self.logger.info("Context test")
        
        with open(self.test_log_file, 'r') as f:
            content = f.read()
        
        self.assertIn("Context", content)
    
    def test_metrics(self):
        """Test metric recording."""
        self.logger.metric("test_metric", 42)
        self.logger.increment_metric("counter")
        self.logger.increment_metric("counter")
        
        metrics = self.logger.get_metrics()
        
        self.assertEqual(metrics["test_metric"], 42)
        self.assertEqual(metrics["counter"], 2)
    
    def test_operation_logging(self):
        """Test operation start/end logging."""
        self.logger.log_operation_start("test_operation", {"param": "value"})
        self.logger.log_operation_end("test_operation", True, {"result": "success"})
        
        with open(self.test_log_file, 'r') as f:
            content = f.read()
        
        self.assertIn("Starting operation", content)
        self.assertIn("completed successfully", content)


class TestValidation(unittest.TestCase):
    """Test validation functionality."""
    
    def setUp(self):
        """Set up validator."""
        self.validator = Validator(ValidationRules())
    
    def test_valid_technique_id(self):
        """Test validation of valid technique IDs."""
        # Valid parent technique
        result = self.validator.validate_technique_id("T1059")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, "T1059")
        
        # Valid sub-technique
        result = self.validator.validate_technique_id("T1059.001")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, "T1059.001")
        
        # Lowercase (should be normalized)
        result = self.validator.validate_technique_id("t1059")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, "T1059")
    
    def test_invalid_technique_id(self):
        """Test validation of invalid technique IDs."""
        # Empty
        result = self.validator.validate_technique_id("")
        self.assertFalse(result.is_valid)
        
        # Wrong format
        result = self.validator.validate_technique_id("T123")
        self.assertFalse(result.is_valid)
        
        result = self.validator.validate_technique_id("1059")
        self.assertFalse(result.is_valid)
        
        result = self.validator.validate_technique_id("INVALID")
        self.assertFalse(result.is_valid)
    
    def test_technique_list_validation(self):
        """Test validation of technique lists."""
        # Valid list
        techniques = ["T1059", "T1003", "T1055"]
        result = self.validator.validate_technique_list(techniques)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.sanitized_value), 3)
        
        # List with duplicates
        techniques = ["T1059", "T1059", "T1003"]
        result = self.validator.validate_technique_list(techniques)
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.sanitized_value), 2)  # Deduplicated
        self.assertGreater(len(result.warnings), 0)
        
        # Mixed valid and invalid
        techniques = ["T1059", "INVALID", "T1003"]
        result = self.validator.validate_technique_list(techniques)
        self.assertFalse(result.is_valid)
        self.assertGreater(len(result.errors), 0)
    
    def test_search_terms_validation(self):
        """Test validation of search terms."""
        # Valid terms
        result = self.validator.validate_search_terms(["energy", "financial"])
        self.assertTrue(result.is_valid)
        
        # Empty list
        result = self.validator.validate_search_terms([])
        self.assertFalse(result.is_valid)
        
        # Terms with special characters
        result = self.validator.validate_search_terms(["test<script>"])
        self.assertTrue(result.is_valid)
        self.assertGreater(len(result.warnings), 0)
    
    def test_file_path_validation(self):
        """Test file path validation."""
        # Create a test file
        test_file = TestUtilities.create_temp_file("test content", ".txt")
        
        try:
            # Valid file
            result = self.validator.validate_file_path(test_file)
            self.assertTrue(result.is_valid)
            
            # Non-existent file
            result = self.validator.validate_file_path("/nonexistent/file.txt")
            self.assertFalse(result.is_valid)
            
            # Wrong extension
            result = self.validator.validate_file_path(
                test_file,
                allowed_extensions=['.json']
            )
            self.assertFalse(result.is_valid)
            
        finally:
            os.remove(test_file)
    
    def test_threshold_validation(self):
        """Test threshold validation."""
        # Valid threshold
        result = self.validator.validate_threshold(5)
        self.assertTrue(result.is_valid)
        
        # Negative threshold
        result = self.validator.validate_threshold(-1)
        self.assertFalse(result.is_valid)
        
        # Very high threshold (warning)
        result = self.validator.validate_threshold(100)
        self.assertTrue(result.is_valid)
        self.assertGreater(len(result.warnings), 0)
        
        # Not an integer
        result = self.validator.validate_threshold(5.5)
        self.assertFalse(result.is_valid)
    
    def test_json_structure_validation(self):
        """Test JSON structure validation."""
        # Valid structure
        data = {"name": "test", "value": 123}
        result = self.validator.validate_json_structure(data, ["name", "value"])
        self.assertTrue(result.is_valid)
        
        # Missing required field
        data = {"name": "test"}
        result = self.validator.validate_json_structure(data, ["name", "value"])
        self.assertFalse(result.is_valid)
        
        # Not a dict
        result = self.validator.validate_json_structure([], ["field"])
        self.assertFalse(result.is_valid)
    
    def test_platform_validation(self):
        """Test platform list validation."""
        # Valid platforms
        result = self.validator.validate_platform_list(["windows", "linux"])
        self.assertTrue(result.is_valid)
        
        # Invalid platform
        result = self.validator.validate_platform_list(["invalid_platform"])
        self.assertTrue(result.is_valid)  # Still valid but with warnings
        self.assertGreater(len(result.warnings), 0)
    
    def test_config_validation(self):
        """Test full configuration validation."""
        config = HeatmapConfig()
        config.threshold = 5
        config.platforms = ["windows", "linux"]
        
        result = self.validator.validate_config(config)
        self.assertTrue(result.is_valid)


if __name__ == '__main__':
    unittest.main()
