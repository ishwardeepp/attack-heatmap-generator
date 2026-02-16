"""
Validation module for MITRE ATT&CK Heatmap Generator.
Provides comprehensive input validation with detailed error messages.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

from .config import ValidationRules, InputFormat
from .logger import get_logger


@dataclass
class ValidationResult:
    """Result of a validation operation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    sanitized_value: Any = None
    
    def __bool__(self):
        """Allow using result in boolean context."""
        return self.is_valid


class Validator:
    """
    Comprehensive validator for all input types.
    """
    
    def __init__(self, rules: ValidationRules):
        """
        Initialize validator with rules.
        
        Args:
            rules: ValidationRules instance
        """
        self.rules = rules
        self.logger = get_logger()
        self.technique_pattern = re.compile(rules.allowed_technique_pattern)
    
    def validate_technique_id(self, technique_id: str) -> ValidationResult:
        """
        Validate a MITRE ATT&CK technique ID.
        
        Args:
            technique_id: Technique ID to validate (e.g., "T1059", "T1059.001")
            
        Returns:
            ValidationResult with validation status
        """
        self.logger.debug(f"Validating technique ID: {technique_id}")
        
        errors = []
        warnings = []
        
        # Check if empty
        if not technique_id or not technique_id.strip():
            errors.append("Technique ID cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Normalize
        technique_id = technique_id.strip().upper()
        
        # Check format
        if not self.technique_pattern.match(technique_id):
            errors.append(
                f"Invalid technique ID format: '{technique_id}'. "
                f"Expected format: T#### or T####.### (e.g., T1059 or T1059.001)"
            )
            return ValidationResult(False, errors, warnings)
        
        # Check for deprecated patterns (just warning)
        if technique_id.startswith("T0"):
            warnings.append(
                f"Technique ID '{technique_id}' may be from ICS matrix. "
                "Ensure you're using the correct matrix type."
            )
        
        self.logger.debug(f"Technique ID validated successfully: {technique_id}")
        return ValidationResult(True, errors, warnings, sanitized_value=technique_id)
    
    def validate_technique_list(self, techniques: List[str]) -> ValidationResult:
        """
        Validate a list of technique IDs.
        
        Args:
            techniques: List of technique IDs
            
        Returns:
            ValidationResult with validation status
        """
        self.logger.debug(f"Validating technique list with {len(techniques)} items")
        
        errors = []
        warnings = []
        valid_techniques = []
        
        # Check list size
        if len(techniques) > self.rules.max_technique_ids:
            errors.append(
                f"Too many technique IDs: {len(techniques)} "
                f"(maximum: {self.rules.max_technique_ids})"
            )
            return ValidationResult(False, errors, warnings)
        
        if len(techniques) == 0:
            errors.append("Technique list cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Validate each technique
        for idx, tech in enumerate(techniques):
            result = self.validate_technique_id(tech)
            if result.is_valid:
                valid_techniques.append(result.sanitized_value)
            else:
                errors.extend([f"Item {idx}: {err}" for err in result.errors])
            warnings.extend(result.warnings)
        
        # Check for duplicates
        unique_count = len(set(valid_techniques))
        if unique_count < len(valid_techniques):
            duplicate_count = len(valid_techniques) - unique_count
            warnings.append(f"Found {duplicate_count} duplicate technique IDs (will be deduplicated)")
        
        if errors:
            return ValidationResult(False, errors, warnings)
        
        self.logger.info(f"Validated {len(valid_techniques)} unique technique IDs")
        return ValidationResult(
            True, 
            errors, 
            warnings, 
            sanitized_value=list(set(valid_techniques))
        )
    
    def validate_search_terms(self, search_terms: List[str]) -> ValidationResult:
        """
        Validate search terms for group filtering.
        
        Args:
            search_terms: List of search terms
            
        Returns:
            ValidationResult with validation status
        """
        self.logger.debug(f"Validating {len(search_terms)} search terms")
        
        errors = []
        warnings = []
        sanitized_terms = []
        
        if len(search_terms) > self.rules.max_search_terms:
            errors.append(
                f"Too many search terms: {len(search_terms)} "
                f"(maximum: {self.rules.max_search_terms})"
            )
            return ValidationResult(False, errors, warnings)
        
        if len(search_terms) == 0:
            errors.append("Search terms cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        for term in search_terms:
            if not term or not term.strip():
                warnings.append("Ignoring empty search term")
                continue
            
            # Check for potentially problematic characters
            if re.search(r'[<>"\']', term):
                warnings.append(
                    f"Search term '{term}' contains special characters that may affect results"
                )
            
            # Check length
            if len(term) < 2:
                warnings.append(f"Very short search term: '{term}' (may return too many results)")
            elif len(term) > 100:
                warnings.append(f"Very long search term: '{term}' (may not match anything)")
            
            sanitized_terms.append(term.strip())
        
        if not sanitized_terms:
            errors.append("No valid search terms provided after filtering")
            return ValidationResult(False, errors, warnings)
        
        self.logger.info(f"Validated {len(sanitized_terms)} search terms")
        return ValidationResult(True, errors, warnings, sanitized_value=sanitized_terms)
    
    def validate_file_path(
        self, 
        file_path: str, 
        must_exist: bool = True,
        allowed_extensions: Optional[List[str]] = None
    ) -> ValidationResult:
        """
        Validate a file path.
        
        Args:
            file_path: Path to file
            must_exist: Whether file must exist
            allowed_extensions: List of allowed file extensions (e.g., ['.json', '.csv'])
            
        Returns:
            ValidationResult with validation status
        """
        self.logger.debug(f"Validating file path: {file_path}")
        
        errors = []
        warnings = []
        
        if not file_path or not file_path.strip():
            errors.append("File path cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        path = Path(file_path)
        
        # Check existence
        if must_exist and not path.exists():
            errors.append(f"File does not exist: {file_path}")
            return ValidationResult(False, errors, warnings)
        
        if must_exist and not path.is_file():
            errors.append(f"Path is not a file: {file_path}")
            return ValidationResult(False, errors, warnings)
        
        # Check extension
        if allowed_extensions:
            if path.suffix.lower() not in [ext.lower() for ext in allowed_extensions]:
                errors.append(
                    f"Invalid file extension: {path.suffix}. "
                    f"Allowed: {', '.join(allowed_extensions)}"
                )
                return ValidationResult(False, errors, warnings)
        
        # Check file size
        if must_exist:
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > self.rules.max_file_size_mb:
                errors.append(
                    f"File too large: {size_mb:.2f}MB "
                    f"(maximum: {self.rules.max_file_size_mb}MB)"
                )
                return ValidationResult(False, errors, warnings)
            
            if size_mb > self.rules.max_file_size_mb * 0.8:
                warnings.append(
                    f"Large file detected: {size_mb:.2f}MB. "
                    "Processing may take longer."
                )
        
        self.logger.debug(f"File path validated: {file_path}")
        return ValidationResult(True, errors, warnings, sanitized_value=str(path.absolute()))
    
    def validate_threshold(self, threshold: int) -> ValidationResult:
        """
        Validate a threshold value.
        
        Args:
            threshold: Threshold value
            
        Returns:
            ValidationResult with validation status
        """
        self.logger.debug(f"Validating threshold: {threshold}")
        
        errors = []
        warnings = []
        
        if not isinstance(threshold, int):
            errors.append(f"Threshold must be an integer, got {type(threshold).__name__}")
            return ValidationResult(False, errors, warnings)
        
        if threshold < self.rules.min_threshold:
            errors.append(
                f"Threshold too low: {threshold} "
                f"(minimum: {self.rules.min_threshold})"
            )
            return ValidationResult(False, errors, warnings)
        
        if threshold > self.rules.max_threshold:
            errors.append(
                f"Threshold too high: {threshold} "
                f"(maximum: {self.rules.max_threshold})"
            )
            return ValidationResult(False, errors, warnings)
        
        if threshold > 50:
            warnings.append(
                f"High threshold value: {threshold}. "
                "This may filter out most techniques."
            )
        
        self.logger.debug(f"Threshold validated: {threshold}")
        return ValidationResult(True, errors, warnings, sanitized_value=threshold)
    
    def validate_json_structure(self, data: Dict[str, Any], required_fields: List[str]) -> ValidationResult:
        """
        Validate JSON data structure.
        
        Args:
            data: Dictionary to validate
            required_fields: List of required field names
            
        Returns:
            ValidationResult with validation status
        """
        self.logger.debug(f"Validating JSON structure with {len(required_fields)} required fields")
        
        errors = []
        warnings = []
        
        if not isinstance(data, dict):
            errors.append(f"Expected dictionary, got {type(data).__name__}")
            return ValidationResult(False, errors, warnings)
        
        # Check required fields
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            errors.append(f"Missing required fields: {', '.join(missing_fields)}")
            return ValidationResult(False, errors, warnings)
        
        # Check for empty values in required fields
        empty_fields = [
            field for field in required_fields 
            if not data.get(field) and data.get(field) != 0
        ]
        if empty_fields:
            warnings.append(f"Empty required fields: {', '.join(empty_fields)}")
        
        self.logger.debug("JSON structure validated successfully")
        return ValidationResult(True, errors, warnings, sanitized_value=data)
    
    def validate_platform_list(self, platforms: List[str]) -> ValidationResult:
        """
        Validate platform filter list.
        
        Args:
            platforms: List of platform names
            
        Returns:
            ValidationResult with validation status
        """
        from .config import PLATFORM_MAPPINGS
        
        self.logger.debug(f"Validating {len(platforms)} platforms")
        
        errors = []
        warnings = []
        valid_platforms = []
        
        valid_platform_names = list(PLATFORM_MAPPINGS.keys())
        
        for platform in platforms:
            platform_lower = platform.lower()
            if platform_lower in valid_platform_names:
                valid_platforms.append(platform_lower)
            else:
                warnings.append(
                    f"Unknown platform: '{platform}'. "
                    f"Valid platforms: {', '.join(valid_platform_names)}"
                )
        
        if not valid_platforms and platforms:
            errors.append("No valid platforms provided")
            return ValidationResult(False, errors, warnings)
        
        self.logger.info(f"Validated {len(valid_platforms)} platforms")
        return ValidationResult(True, errors, warnings, sanitized_value=valid_platforms)
    
    def validate_config(self, config: Any) -> ValidationResult:
        """
        Validate an entire configuration object.
        
        Args:
            config: HeatmapConfig instance
            
        Returns:
            ValidationResult with validation status
        """
        self.logger.info("Validating configuration")
        
        errors = []
        warnings = []
        
        # Validate threshold
        threshold_result = self.validate_threshold(config.threshold)
        errors.extend(threshold_result.errors)
        warnings.extend(threshold_result.warnings)
        
        # Validate platforms if specified
        if config.platforms:
            platform_result = self.validate_platform_list(config.platforms)
            errors.extend(platform_result.errors)
            warnings.extend(platform_result.warnings)
        
        # Validate output directory
        output_path = Path(config.output_directory)
        if not output_path.exists():
            try:
                output_path.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"Created output directory: {config.output_directory}")
            except Exception as e:
                errors.append(f"Cannot create output directory: {e}")
        
        # Validate cache configuration
        if config.cache.enabled:
            cache_path = Path(config.cache.cache_dir)
            if not cache_path.exists():
                try:
                    cache_path.mkdir(parents=True, exist_ok=True)
                    self.logger.info(f"Created cache directory: {config.cache.cache_dir}")
                except Exception as e:
                    warnings.append(f"Cannot create cache directory: {e}. Caching will be disabled.")
        
        if errors:
            self.logger.error(f"Configuration validation failed with {len(errors)} errors")
            return ValidationResult(False, errors, warnings)
        
        self.logger.info("Configuration validated successfully")
        if warnings:
            self.logger.warning(f"Configuration has {len(warnings)} warnings")
        
        return ValidationResult(True, errors, warnings, sanitized_value=config)
