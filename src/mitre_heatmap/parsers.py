"""
Input parsers for different TTP input formats.
Supports JSON, CSV, STIX bundles, and text extraction.
"""

import json
import csv
import re
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from abc import ABC, abstractmethod

from .config import InputFormat
from .logger import get_logger
from .validator import Validator, ValidationResult


class InputParser(ABC):
    """Base class for input parsers."""
    
    def __init__(self, validator: Validator):
        """
        Initialize parser.
        
        Args:
            validator: Validator instance
        """
        self.validator = validator
        self.logger = get_logger()
    
    @abstractmethod
    def parse(self, input_data: Any) -> ValidationResult:
        """
        Parse input data.
        
        Args:
            input_data: Data to parse
            
        Returns:
            ValidationResult with parsed technique IDs
        """
        pass


class TechniqueListParser(InputParser):
    """Parser for simple list of technique IDs."""
    
    def parse(self, input_data: List[str]) -> ValidationResult:
        """
        Parse a list of technique IDs.
        
        Args:
            input_data: List of technique ID strings
            
        Returns:
            ValidationResult with validated technique IDs
        """
        self.logger.log_operation_start("parse_technique_list", {"count": len(input_data)})
        
        result = self.validator.validate_technique_list(input_data)
        
        self.logger.log_operation_end(
            "parse_technique_list",
            result.is_valid,
            {"parsed_count": len(result.sanitized_value) if result.is_valid else 0}
        )
        
        return result


class JSONFileParser(InputParser):
    """Parser for JSON files containing technique data."""
    
    SUPPORTED_FORMATS = {
        'navigator': ['techniques', 'technique'],
        'simple_list': ['ttps', 'techniques', 'technique_ids'],
        'attack_flow': ['objects'],
        'custom': ['data', 'items', 'entries']
    }
    
    def parse(self, file_path: str) -> ValidationResult:
        """
        Parse JSON file.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            ValidationResult with parsed technique IDs
        """
        self.logger.log_operation_start("parse_json_file", {"file": file_path})
        
        # Validate file
        file_result = self.validator.validate_file_path(
            file_path,
            must_exist=True,
            allowed_extensions=['.json']
        )
        
        if not file_result.is_valid:
            return file_result
        
        # Load JSON
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.logger.info(f"Loaded JSON file: {file_path}")
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON file: {e}"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        except Exception as e:
            error_msg = f"Error reading file: {e}"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        # Extract techniques
        techniques = self._extract_techniques_from_json(data)
        
        if not techniques:
            error_msg = "No techniques found in JSON file"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        self.logger.info(f"Extracted {len(techniques)} techniques from JSON")
        
        # Validate techniques
        result = self.validator.validate_technique_list(techniques)
        
        self.logger.log_operation_end(
            "parse_json_file",
            result.is_valid,
            {"parsed_count": len(result.sanitized_value) if result.is_valid else 0}
        )
        
        return result
    
    def _extract_techniques_from_json(self, data: Any) -> List[str]:
        """Extract technique IDs from JSON data."""
        techniques = []
        
        # Try different JSON structures
        if isinstance(data, list):
            # Direct list of techniques
            for item in data:
                tech_id = self._extract_technique_id_from_item(item)
                if tech_id:
                    techniques.append(tech_id)
        
        elif isinstance(data, dict):
            # Try known field names
            for format_type, field_names in self.SUPPORTED_FORMATS.items():
                for field in field_names:
                    if field in data:
                        items = data[field]
                        if isinstance(items, list):
                            for item in items:
                                tech_id = self._extract_technique_id_from_item(item)
                                if tech_id:
                                    techniques.append(tech_id)
                        break
                if techniques:
                    self.logger.debug(f"Detected JSON format: {format_type}")
                    break
            
            # If still no techniques, try ATT&CK Navigator format
            if not techniques and 'techniques' in data:
                nav_techniques = data['techniques']
                if isinstance(nav_techniques, list):
                    for tech in nav_techniques:
                        if isinstance(tech, dict) and 'techniqueID' in tech:
                            techniques.append(tech['techniqueID'])
        
        return techniques
    
    def _extract_technique_id_from_item(self, item: Any) -> Optional[str]:
        """Extract technique ID from a single item."""
        if isinstance(item, str):
            # Direct string
            return item
        
        elif isinstance(item, dict):
            # Try common field names
            for field in ['techniqueID', 'technique_id', 'id', 'technique', 'ttp', 'attack_id']:
                if field in item:
                    return str(item[field])
        
        return None


class CSVFileParser(InputParser):
    """Parser for CSV files containing technique data."""
    
    def parse(self, file_path: str, technique_column: Optional[str] = None) -> ValidationResult:
        """
        Parse CSV file.
        
        Args:
            file_path: Path to CSV file
            technique_column: Name of column containing technique IDs (auto-detect if None)
            
        Returns:
            ValidationResult with parsed technique IDs
        """
        self.logger.log_operation_start("parse_csv_file", {"file": file_path})
        
        # Validate file
        file_result = self.validator.validate_file_path(
            file_path,
            must_exist=True,
            allowed_extensions=['.csv', '.tsv']
        )
        
        if not file_result.is_valid:
            return file_result
        
        # Determine delimiter
        delimiter = '\t' if file_path.endswith('.tsv') else ','
        
        # Read CSV
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter=delimiter)
                rows = list(reader)
            
            self.logger.info(f"Loaded CSV file with {len(rows)} rows")
            
        except Exception as e:
            error_msg = f"Error reading CSV file: {e}"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        if not rows:
            error_msg = "CSV file is empty"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        # Detect technique column
        if not technique_column:
            technique_column = self._detect_technique_column(rows[0].keys())
        
        if not technique_column:
            error_msg = (
                "Could not auto-detect technique column. "
                "Please specify column name explicitly."
            )
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        self.logger.debug(f"Using column: {technique_column}")
        
        # Extract techniques
        techniques = []
        for row in rows:
            if technique_column in row:
                tech_id = row[technique_column].strip()
                if tech_id:
                    techniques.append(tech_id)
        
        self.logger.info(f"Extracted {len(techniques)} techniques from CSV")
        
        # Validate techniques
        result = self.validator.validate_technique_list(techniques)
        
        self.logger.log_operation_end(
            "parse_csv_file",
            result.is_valid,
            {"parsed_count": len(result.sanitized_value) if result.is_valid else 0}
        )
        
        return result
    
    def _detect_technique_column(self, columns: List[str]) -> Optional[str]:
        """Auto-detect which column contains technique IDs."""
        # Common column names
        candidate_names = [
            'technique_id', 'techniqueid', 'technique id',
            'ttp', 'ttps', 'technique', 'techniques',
            'attack_id', 'attackid', 'attack id',
            'mitre_id', 'mitreid', 'mitre id',
            'id'
        ]
        
        columns_lower = {col.lower(): col for col in columns}
        
        for candidate in candidate_names:
            if candidate in columns_lower:
                return columns_lower[candidate]
        
        return None


class STIXBundleParser(InputParser):
    """Parser for STIX 2.x bundles."""
    
    def parse(self, file_path: str) -> ValidationResult:
        """
        Parse STIX bundle file.
        
        Args:
            file_path: Path to STIX bundle JSON file
            
        Returns:
            ValidationResult with parsed technique IDs
        """
        self.logger.log_operation_start("parse_stix_bundle", {"file": file_path})
        
        # Validate file
        file_result = self.validator.validate_file_path(
            file_path,
            must_exist=True,
            allowed_extensions=['.json']
        )
        
        if not file_result.is_valid:
            return file_result
        
        # Load STIX bundle
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
            
            self.logger.info(f"Loaded STIX bundle: {file_path}")
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid STIX bundle JSON: {e}"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        except Exception as e:
            error_msg = f"Error reading STIX bundle: {e}"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        # Validate STIX structure
        if not isinstance(bundle, dict) or bundle.get('type') != 'bundle':
            error_msg = "Invalid STIX bundle: missing 'type': 'bundle'"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        objects = bundle.get('objects', [])
        if not objects:
            error_msg = "STIX bundle contains no objects"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        self.logger.info(f"Processing {len(objects)} STIX objects")
        
        # Extract techniques from attack-pattern objects
        techniques = []
        for obj in objects:
            if obj.get('type') == 'attack-pattern':
                tech_id = self._extract_technique_id_from_stix(obj)
                if tech_id:
                    techniques.append(tech_id)
        
        if not techniques:
            error_msg = "No ATT&CK techniques found in STIX bundle"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        self.logger.info(f"Extracted {len(techniques)} techniques from STIX bundle")
        
        # Validate techniques
        result = self.validator.validate_technique_list(techniques)
        
        self.logger.log_operation_end(
            "parse_stix_bundle",
            result.is_valid,
            {"parsed_count": len(result.sanitized_value) if result.is_valid else 0}
        )
        
        return result
    
    def _extract_technique_id_from_stix(self, attack_pattern: Dict) -> Optional[str]:
        """Extract technique ID from STIX attack-pattern object."""
        external_refs = attack_pattern.get('external_references', [])
        
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        
        return None


class TextExtractionParser(InputParser):
    """Parser that extracts technique IDs from free text."""
    
    # Regex pattern for technique IDs
    TECHNIQUE_PATTERN = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b', re.IGNORECASE)
    
    def parse(self, text: str) -> ValidationResult:
        """
        Extract technique IDs from text.
        
        Args:
            text: Text to parse
            
        Returns:
            ValidationResult with extracted technique IDs
        """
        self.logger.log_operation_start("parse_text", {"length": len(text)})
        
        if not text or not text.strip():
            error_msg = "Text is empty"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        # Extract technique IDs using regex
        matches = self.TECHNIQUE_PATTERN.findall(text)
        
        # Normalize to uppercase
        techniques = [match.upper() for match in matches]
        
        # Remove duplicates while preserving order
        seen = set()
        unique_techniques = []
        for tech in techniques:
            if tech not in seen:
                seen.add(tech)
                unique_techniques.append(tech)
        
        if not unique_techniques:
            error_msg = "No technique IDs found in text"
            self.logger.warning(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        self.logger.info(f"Extracted {len(unique_techniques)} unique technique IDs from text")
        
        # Validate techniques
        result = self.validator.validate_technique_list(unique_techniques)
        
        self.logger.log_operation_end(
            "parse_text",
            result.is_valid,
            {"parsed_count": len(result.sanitized_value) if result.is_valid else 0}
        )
        
        return result
    
    def parse_file(self, file_path: str) -> ValidationResult:
        """
        Extract technique IDs from a text file.
        
        Args:
            file_path: Path to text file
            
        Returns:
            ValidationResult with extracted technique IDs
        """
        # Validate file
        file_result = self.validator.validate_file_path(
            file_path,
            must_exist=True,
            allowed_extensions=['.txt', '.md', '.log', '.report']
        )
        
        if not file_result.is_valid:
            return file_result
        
        # Read file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
            
            self.logger.info(f"Read text file: {file_path}")
            
        except Exception as e:
            error_msg = f"Error reading text file: {e}"
            self.logger.error(error_msg)
            return ValidationResult(False, [error_msg], [])
        
        # Parse text
        return self.parse(text)


class InputParserFactory:
    """Factory for creating appropriate input parsers."""
    
    @staticmethod
    def create_parser(
        input_format: InputFormat,
        validator: Validator
    ) -> InputParser:
        """
        Create appropriate parser for input format.
        
        Args:
            input_format: Type of input format
            validator: Validator instance
            
        Returns:
            InputParser instance
        """
        parsers = {
            InputFormat.TECHNIQUE_LIST: TechniqueListParser,
            InputFormat.JSON_FILE: JSONFileParser,
            InputFormat.CSV_FILE: CSVFileParser,
            InputFormat.STIX_BUNDLE: STIXBundleParser,
            InputFormat.TEXT_EXTRACTION: TextExtractionParser,
        }
        
        parser_class = parsers.get(input_format)
        if not parser_class:
            raise ValueError(f"Unsupported input format: {input_format}")
        
        return parser_class(validator)
