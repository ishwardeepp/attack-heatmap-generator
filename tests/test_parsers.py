"""
Comprehensive test suite for MITRE ATT&CK Heatmap Generator.
Part 2: Parser and generator tests.
"""

import unittest
import tempfile
import json
import csv
import os
from pathlib import Path

# Import modules to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from mitre_heatmap.config import ValidationRules, InputFormat, ScoringAlgorithm
from mitre_heatmap.validator import Validator
from mitre_heatmap.parsers import (
    TechniqueListParser,
    JSONFileParser,
    CSVFileParser,
    STIXBundleParser,
    TextExtractionParser,
    InputParserFactory
)
from mitre_heatmap.generator import TechniqueScorer

# Import test utilities
from test_core import TestUtilities


class TestTechniqueListParser(unittest.TestCase):
    """Test technique list parser."""
    
    def setUp(self):
        """Set up parser."""
        self.validator = Validator(ValidationRules())
        self.parser = TechniqueListParser(self.validator)
    
    def test_parse_valid_list(self):
        """Test parsing valid technique list."""
        techniques = ["T1059", "T1003", "T1055.001"]
        result = self.parser.parse(techniques)
        
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.sanitized_value), 3)
    
    def test_parse_with_duplicates(self):
        """Test parsing list with duplicates."""
        techniques = ["T1059", "T1059", "T1003"]
        result = self.parser.parse(techniques)
        
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.sanitized_value), 2)
        self.assertGreater(len(result.warnings), 0)
    
    def test_parse_invalid_techniques(self):
        """Test parsing invalid techniques."""
        techniques = ["INVALID", "T1059"]
        result = self.parser.parse(techniques)
        
        self.assertFalse(result.is_valid)
        self.assertGreater(len(result.errors), 0)


class TestJSONFileParser(unittest.TestCase):
    """Test JSON file parser."""
    
    def setUp(self):
        """Set up parser."""
        self.validator = Validator(ValidationRules())
        self.parser = JSONFileParser(self.validator)
    
    def test_parse_simple_list(self):
        """Test parsing simple JSON list."""
        data = ["T1059", "T1003", "T1055"]
        json_file = TestUtilities.create_temp_json(data)
        
        try:
            result = self.parser.parse(json_file)
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 3)
        finally:
            os.remove(json_file)
    
    def test_parse_navigator_format(self):
        """Test parsing ATT&CK Navigator format."""
        data = {
            "name": "Test Layer",
            "techniques": [
                {"techniqueID": "T1059", "score": 5},
                {"techniqueID": "T1003", "score": 3}
            ]
        }
        json_file = TestUtilities.create_temp_json(data)
        
        try:
            result = self.parser.parse(json_file)
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 2)
        finally:
            os.remove(json_file)
    
    def test_parse_custom_format(self):
        """Test parsing custom JSON format."""
        data = {
            "ttps": ["T1059", "T1003"],
            "metadata": {"source": "test"}
        }
        json_file = TestUtilities.create_temp_json(data)
        
        try:
            result = self.parser.parse(json_file)
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 2)
        finally:
            os.remove(json_file)
    
    def test_parse_invalid_json(self):
        """Test parsing invalid JSON file."""
        json_file = TestUtilities.create_temp_file("not valid json", ".json")
        
        try:
            result = self.parser.parse(json_file)
            
            self.assertFalse(result.is_valid)
            self.assertGreater(len(result.errors), 0)
        finally:
            os.remove(json_file)
    
    def test_parse_empty_json(self):
        """Test parsing JSON with no techniques."""
        data = {"name": "empty", "data": []}
        json_file = TestUtilities.create_temp_json(data)
        
        try:
            result = self.parser.parse(json_file)
            
            self.assertFalse(result.is_valid)
        finally:
            os.remove(json_file)


class TestCSVFileParser(unittest.TestCase):
    """Test CSV file parser."""
    
    def setUp(self):
        """Set up parser."""
        self.validator = Validator(ValidationRules())
        self.parser = CSVFileParser(self.validator)
    
    def test_parse_csv_with_header(self):
        """Test parsing CSV with header row."""
        csv_file = tempfile.mktemp(suffix='.csv')
        
        try:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['technique_id', 'name', 'tactic'])
                writer.writerow(['T1059', 'Command and Scripting Interpreter', 'Execution'])
                writer.writerow(['T1003', 'OS Credential Dumping', 'Credential Access'])
                writer.writerow(['T1055', 'Process Injection', 'Defense Evasion'])
            
            result = self.parser.parse(csv_file)
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 3)
        finally:
            if os.path.exists(csv_file):
                os.remove(csv_file)
    
    def test_parse_csv_explicit_column(self):
        """Test parsing CSV with explicit column name."""
        csv_file = tempfile.mktemp(suffix='.csv')
        
        try:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ttp', 'description'])
                writer.writerow(['T1059', 'Test'])
                writer.writerow(['T1003', 'Test'])
            
            result = self.parser.parse(csv_file, technique_column='ttp')
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 2)
        finally:
            if os.path.exists(csv_file):
                os.remove(csv_file)
    
    def test_parse_tsv(self):
        """Test parsing TSV file."""
        tsv_file = tempfile.mktemp(suffix='.tsv')
        
        try:
            with open(tsv_file, 'w') as f:
                f.write("technique_id\tname\n")
                f.write("T1059\tPowerShell\n")
                f.write("T1003\tLSASS\n")
            
            result = self.parser.parse(tsv_file)
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 2)
        finally:
            if os.path.exists(tsv_file):
                os.remove(tsv_file)
    
    def test_parse_empty_csv(self):
        """Test parsing empty CSV."""
        csv_file = TestUtilities.create_temp_file("", ".csv")
        
        try:
            result = self.parser.parse(csv_file)
            
            self.assertFalse(result.is_valid)
        finally:
            os.remove(csv_file)


class TestSTIXBundleParser(unittest.TestCase):
    """Test STIX bundle parser."""
    
    def setUp(self):
        """Set up parser."""
        self.validator = Validator(ValidationRules())
        self.parser = STIXBundleParser(self.validator)
    
    def test_parse_valid_bundle(self):
        """Test parsing valid STIX bundle."""
        bundle = TestUtilities.create_sample_stix_bundle()
        bundle_file = TestUtilities.create_temp_json(bundle)
        
        try:
            result = self.parser.parse(bundle_file)
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 2)
            self.assertIn("T1059.001", result.sanitized_value)
            self.assertIn("T1003.001", result.sanitized_value)
        finally:
            os.remove(bundle_file)
    
    def test_parse_invalid_bundle(self):
        """Test parsing invalid STIX bundle."""
        data = {"type": "not-a-bundle"}
        bundle_file = TestUtilities.create_temp_json(data)
        
        try:
            result = self.parser.parse(bundle_file)
            
            self.assertFalse(result.is_valid)
            self.assertGreater(len(result.errors), 0)
        finally:
            os.remove(bundle_file)
    
    def test_parse_empty_bundle(self):
        """Test parsing STIX bundle with no attack patterns."""
        bundle = {
            "type": "bundle",
            "id": "bundle--001",
            "objects": [
                {"type": "indicator", "id": "indicator--001"}
            ]
        }
        bundle_file = TestUtilities.create_temp_json(bundle)
        
        try:
            result = self.parser.parse(bundle_file)
            
            self.assertFalse(result.is_valid)
        finally:
            os.remove(bundle_file)


class TestTextExtractionParser(unittest.TestCase):
    """Test text extraction parser."""
    
    def setUp(self):
        """Set up parser."""
        self.validator = Validator(ValidationRules())
        self.parser = TextExtractionParser(self.validator)
    
    def test_parse_text_with_techniques(self):
        """Test parsing text containing technique IDs."""
        text = """
        The threat actor used T1059.001 (PowerShell) for initial execution.
        They then performed credential dumping using T1003.001.
        Process injection (T1055) was observed for defense evasion.
        """
        
        result = self.parser.parse(text)
        
        self.assertTrue(result.is_valid)
        self.assertGreaterEqual(len(result.sanitized_value), 3)
        self.assertIn("T1059.001", result.sanitized_value)
        self.assertIn("T1003.001", result.sanitized_value)
        self.assertIn("T1055", result.sanitized_value)
    
    def test_parse_text_case_insensitive(self):
        """Test parsing with mixed case technique IDs."""
        text = "Observed techniques: t1059, T1003, t1055.001"
        
        result = self.parser.parse(text)
        
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.sanitized_value), 3)
        # Should all be uppercase
        for tech in result.sanitized_value:
            self.assertTrue(tech.isupper())
    
    def test_parse_text_duplicates(self):
        """Test parsing text with duplicate techniques."""
        text = "T1059 was used. Later, T1059 was used again. Also T1003."
        
        result = self.parser.parse(text)
        
        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.sanitized_value), 2)  # Deduplicated
    
    def test_parse_text_file(self):
        """Test parsing text file."""
        text = "Report contains T1059, T1003, and T1055.001"
        text_file = TestUtilities.create_temp_file(text, ".txt")
        
        try:
            result = self.parser.parse_file(text_file)
            
            self.assertTrue(result.is_valid)
            self.assertEqual(len(result.sanitized_value), 3)
        finally:
            os.remove(text_file)
    
    def test_parse_empty_text(self):
        """Test parsing empty text."""
        result = self.parser.parse("")
        
        self.assertFalse(result.is_valid)
    
    def test_parse_text_no_techniques(self):
        """Test parsing text with no techniques."""
        text = "This text contains no technique IDs at all."
        
        result = self.parser.parse(text)
        
        self.assertFalse(result.is_valid)


class TestInputParserFactory(unittest.TestCase):
    """Test input parser factory."""
    
    def setUp(self):
        """Set up validator."""
        self.validator = Validator(ValidationRules())
    
    def test_create_technique_list_parser(self):
        """Test creating technique list parser."""
        parser = InputParserFactory.create_parser(
            InputFormat.TECHNIQUE_LIST,
            self.validator
        )
        
        self.assertIsInstance(parser, TechniqueListParser)
    
    def test_create_json_parser(self):
        """Test creating JSON parser."""
        parser = InputParserFactory.create_parser(
            InputFormat.JSON_FILE,
            self.validator
        )
        
        self.assertIsInstance(parser, JSONFileParser)
    
    def test_create_csv_parser(self):
        """Test creating CSV parser."""
        parser = InputParserFactory.create_parser(
            InputFormat.CSV_FILE,
            self.validator
        )
        
        self.assertIsInstance(parser, CSVFileParser)
    
    def test_create_stix_parser(self):
        """Test creating STIX parser."""
        parser = InputParserFactory.create_parser(
            InputFormat.STIX_BUNDLE,
            self.validator
        )
        
        self.assertIsInstance(parser, STIXBundleParser)
    
    def test_create_text_parser(self):
        """Test creating text extraction parser."""
        parser = InputParserFactory.create_parser(
            InputFormat.TEXT_EXTRACTION,
            self.validator
        )
        
        self.assertIsInstance(parser, TextExtractionParser)


class TestTechniqueScorer(unittest.TestCase):
    """Test technique scoring algorithms."""
    
    def setUp(self):
        """Set up test data."""
        self.technique_counts = {
            'T1059': 10,
            'T1003': 5,
            'T1055': 2,
            'T1078': 1
        }
    
    def test_linear_scoring(self):
        """Test linear scoring algorithm."""
        scorer = TechniqueScorer(ScoringAlgorithm.LINEAR)
        scores = scorer.score(self.technique_counts)
        
        self.assertEqual(scores['T1059'], 10.0)
        self.assertEqual(scores['T1003'], 5.0)
        self.assertEqual(scores['T1055'], 2.0)
    
    def test_logarithmic_scoring(self):
        """Test logarithmic scoring algorithm."""
        scorer = TechniqueScorer(ScoringAlgorithm.LOGARITHMIC)
        scores = scorer.score(self.technique_counts)
        
        # log(10+1) ≈ 2.398
        self.assertAlmostEqual(scores['T1059'], 2.398, places=2)
        # log(5+1) ≈ 1.792
        self.assertAlmostEqual(scores['T1003'], 1.792, places=2)
    
    def test_weighted_scoring(self):
        """Test weighted scoring algorithm."""
        weights = {'T1059': 2.0, 'T1003': 1.5}
        scorer = TechniqueScorer(ScoringAlgorithm.WEIGHTED, weights)
        scores = scorer.score(self.technique_counts)
        
        self.assertEqual(scores['T1059'], 20.0)  # 10 * 2.0
        self.assertEqual(scores['T1003'], 7.5)   # 5 * 1.5
        self.assertEqual(scores['T1055'], 2.0)   # 2 * 1.0 (default)
    
    def test_normalized_scoring(self):
        """Test normalized scoring algorithm."""
        scorer = TechniqueScorer(ScoringAlgorithm.NORMALIZED)
        scores = scorer.score(self.technique_counts)
        
        # Max count is 10, so T1059 should be 100
        self.assertEqual(scores['T1059'], 100.0)
        # T1003 is 5, so should be 50
        self.assertEqual(scores['T1003'], 50.0)
        # T1055 is 2, so should be 20
        self.assertEqual(scores['T1055'], 20.0)
    
    def test_empty_counts(self):
        """Test scoring with empty counts."""
        scorer = TechniqueScorer(ScoringAlgorithm.LINEAR)
        scores = scorer.score({})
        
        self.assertEqual(len(scores), 0)


if __name__ == '__main__':
    unittest.main()
