"""
ATT&CK data handler module.
Manages downloading, caching, and querying MITRE ATT&CK data.
"""

import json
import time
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import requests

from .config import MatrixType, AttackConfig, CacheConfig
from .logger import get_logger
from .validator import ValidationResult


class AttackDataCache:
    """Manages caching of ATT&CK STIX data."""
    
    def __init__(self, config: CacheConfig):
        """
        Initialize cache manager.
        
        Args:
            config: CacheConfig instance
        """
        self.config = config
        self.logger = get_logger()
        self.cache_dir = Path(config.cache_dir)
        
        if config.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Cache initialized at: {self.cache_dir}")
    
    def _get_cache_path(self, matrix_type: MatrixType) -> Path:
        """Get cache file path for a matrix type."""
        return self.cache_dir / f"{matrix_type.value}.json"
    
    def _get_metadata_path(self, matrix_type: MatrixType) -> Path:
        """Get metadata file path for a matrix type."""
        return self.cache_dir / f"{matrix_type.value}.meta.json"
    
    def is_cached(self, matrix_type: MatrixType) -> bool:
        """Check if data is cached and still valid."""
        if not self.config.enabled:
            return False
        
        cache_file = self._get_cache_path(matrix_type)
        meta_file = self._get_metadata_path(matrix_type)
        
        if not cache_file.exists() or not meta_file.exists():
            self.logger.debug(f"Cache miss for {matrix_type.value}")
            return False
        
        # Check TTL
        try:
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            cached_time = datetime.fromisoformat(metadata['cached_at'])
            ttl = timedelta(hours=self.config.ttl_hours)
            
            if datetime.now() - cached_time > ttl:
                self.logger.info(f"Cache expired for {matrix_type.value}")
                return False
            
            self.logger.debug(f"Cache hit for {matrix_type.value}")
            return True
            
        except Exception as e:
            self.logger.warning(f"Error reading cache metadata: {e}")
            return False
    
    def get(self, matrix_type: MatrixType) -> Optional[Dict]:
        """
        Get cached data.
        
        Args:
            matrix_type: Matrix type to retrieve
            
        Returns:
            Cached data dict or None
        """
        if not self.is_cached(matrix_type):
            return None
        
        cache_file = self._get_cache_path(matrix_type)
        
        try:
            self.logger.info(f"Loading cached data for {matrix_type.value}")
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            self.logger.metric('cache_hit', 1)
            return data
            
        except Exception as e:
            self.logger.error(f"Error reading cache file: {e}")
            return None
    
    def set(self, matrix_type: MatrixType, data: Dict) -> bool:
        """
        Cache data.
        
        Args:
            matrix_type: Matrix type
            data: Data to cache
            
        Returns:
            True if successful
        """
        if not self.config.enabled:
            return False
        
        cache_file = self._get_cache_path(matrix_type)
        meta_file = self._get_metadata_path(matrix_type)
        
        try:
            # Save data
            with open(cache_file, 'w') as f:
                json.dump(data, f)
            
            # Save metadata
            metadata = {
                'cached_at': datetime.now().isoformat(),
                'matrix_type': matrix_type.value,
                'size_bytes': cache_file.stat().st_size,
            }
            
            with open(meta_file, 'w') as f:
                json.dump(metadata, f)
            
            self.logger.info(f"Cached data for {matrix_type.value}")
            self.logger.metric('cache_write', 1)
            return True
            
        except Exception as e:
            self.logger.error(f"Error writing cache: {e}")
            return False
    
    def clear(self, matrix_type: Optional[MatrixType] = None):
        """
        Clear cache.
        
        Args:
            matrix_type: Specific matrix to clear, or None for all
        """
        if matrix_type:
            cache_file = self._get_cache_path(matrix_type)
            meta_file = self._get_metadata_path(matrix_type)
            
            cache_file.unlink(missing_ok=True)
            meta_file.unlink(missing_ok=True)
            
            self.logger.info(f"Cleared cache for {matrix_type.value}")
        else:
            for file in self.cache_dir.glob("*.json"):
                file.unlink()
            self.logger.info("Cleared all cache")


class AttackDataHandler:
    """
    Handles MITRE ATT&CK data operations.
    """
    
    def __init__(self, attack_config: AttackConfig, cache_config: CacheConfig):
        """
        Initialize data handler.
        
        Args:
            attack_config: AttackConfig instance
            cache_config: CacheConfig instance
        """
        self.config = attack_config
        self.cache = AttackDataCache(cache_config)
        self.logger = get_logger()
        
        self.stix_data: Optional[Dict] = None
        self.techniques: Dict[str, Dict] = {}
        self.groups: Dict[str, Dict] = {}
        self.relationships: List[Dict] = []
        
    def _download_with_retry(self, url: str) -> Optional[Dict]:
        """
        Download data with retry logic.
        
        Args:
            url: URL to download from
            
        Returns:
            Downloaded data or None
        """
        self.logger.info(f"Downloading from: {url}")
        self.logger.log_operation_start("download", {"url": url})
        
        for attempt in range(self.config.retry_attempts):
            try:
                self.logger.debug(f"Download attempt {attempt + 1}/{self.config.retry_attempts}")
                
                response = requests.get(
                    url,
                    timeout=self.config.timeout_seconds,
                    headers={'User-Agent': 'MITRE-ATT&CK-Heatmap-Generator/1.0'}
                )
                response.raise_for_status()
                
                data = response.json()
                
                self.logger.info(f"Successfully downloaded {len(response.content)} bytes")
                self.logger.log_operation_end("download", True, {"size_bytes": len(response.content)})
                self.logger.metric('download_success', 1)
                
                return data
                
            except requests.Timeout:
                self.logger.warning(f"Download timeout on attempt {attempt + 1}")
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay_seconds)
                    
            except requests.RequestException as e:
                self.logger.error(f"Download error on attempt {attempt + 1}: {e}")
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay_seconds)
                else:
                    self.logger.log_operation_end("download", False, {"error": str(e)})
            
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON response: {e}")
                self.logger.log_operation_end("download", False, {"error": "Invalid JSON"})
                return None
        
        self.logger.metric('download_failure', 1)
        return None
    
    def load_attack_data(self, matrix_type: MatrixType = MatrixType.ENTERPRISE) -> bool:
        """
        Load ATT&CK data from cache or download.
        
        Args:
            matrix_type: Type of ATT&CK matrix to load
            
        Returns:
            True if successful
        """
        self.logger.log_operation_start("load_attack_data", {"matrix_type": matrix_type.value})
        
        # Try cache first
        cached_data = self.cache.get(matrix_type)
        if cached_data:
            self.stix_data = cached_data
            self.logger.info("Using cached ATT&CK data")
        else:
            # Determine URL based on matrix type
            url_map = {
                MatrixType.ENTERPRISE: self.config.stix_url,
                MatrixType.MOBILE: self.config.mobile_stix_url,
                MatrixType.ICS: self.config.ics_stix_url,
            }
            
            url = url_map.get(matrix_type)
            if not url:
                self.logger.error(f"No URL configured for matrix type: {matrix_type}")
                return False
            
            # Download
            self.stix_data = self._download_with_retry(url)
            if not self.stix_data:
                self.logger.error("Failed to download ATT&CK data")
                self.logger.log_operation_end("load_attack_data", False)
                return False
            
            # Cache it
            self.cache.set(matrix_type, self.stix_data)
        
        # Parse the data
        if not self._parse_stix_data():
            self.logger.error("Failed to parse ATT&CK data")
            self.logger.log_operation_end("load_attack_data", False)
            return False
        
        self.logger.info(
            f"Loaded {len(self.techniques)} techniques, "
            f"{len(self.groups)} groups, "
            f"{len(self.relationships)} relationships"
        )
        
        self.logger.log_operation_end(
            "load_attack_data", 
            True, 
            {
                "techniques": len(self.techniques),
                "groups": len(self.groups),
                "relationships": len(self.relationships)
            }
        )
        
        return True
    
    def _parse_stix_data(self) -> bool:
        """
        Parse STIX data into usable structures.
        
        Returns:
            True if successful
        """
        try:
            objects = self.stix_data.get('objects', [])
            self.logger.info(f"Parsing {len(objects)} STIX objects")
            
            # Clear existing data
            self.techniques.clear()
            self.groups.clear()
            self.relationships.clear()
            
            # Parse objects
            for obj in objects:
                obj_type = obj.get('type')
                
                if obj_type == 'attack-pattern':
                    # This is a technique - store by STIX ID for relationship lookups
                    stix_id = obj.get('id')
                    if stix_id:
                        self.techniques[stix_id] = obj
                        
                elif obj_type == 'intrusion-set':
                    # This is a group
                    group_id = obj.get('id')
                    if group_id:
                        self.groups[group_id] = obj
                        
                elif obj_type == 'relationship':
                    # This is a relationship
                    self.relationships.append(obj)
            
            self.logger.info(
                f"Parsed {len(self.techniques)} techniques, "
                f"{len(self.groups)} groups, "
                f"{len(self.relationships)} relationships"
            )
            
            # Log data quality metrics
            deprecated_count = sum(
                1 for t in self.techniques.values() 
                if t.get('x_mitre_deprecated', False)
            )
            revoked_count = sum(
                1 for t in self.techniques.values() 
                if t.get('revoked', False)
            )
            
            self.logger.log_data_quality(
                "ATT&CK STIX",
                {
                    "total_techniques": len(self.techniques),
                    "deprecated_techniques": deprecated_count,
                    "revoked_techniques": revoked_count,
                    "total_groups": len(self.groups),
                    "total_relationships": len(self.relationships)
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing STIX data: {e}", exc_info=True)
            return False
    
    def _extract_technique_id(self, technique_obj: Dict) -> Optional[str]:
        """Extract technique ID from STIX object."""
        external_refs = technique_obj.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def search_groups_by_keywords(
        self, 
        keywords: List[str], 
        case_sensitive: bool = False
    ) -> List[Tuple[str, Dict]]:
        """
        Search for groups by keywords in their descriptions.
        
        Args:
            keywords: List of keywords to search for
            case_sensitive: Whether to use case-sensitive search
            
        Returns:
            List of (group_id, group_object) tuples
        """
        self.logger.log_operation_start(
            "search_groups",
            {"keywords": keywords, "case_sensitive": case_sensitive}
        )
        
        matching_groups = []
        
        for group_id, group_obj in self.groups.items():
            # Skip revoked/deprecated groups
            if group_obj.get('revoked') or group_obj.get('x_mitre_deprecated'):
                continue
            
            description = group_obj.get('description', '')
            name = group_obj.get('name', '')
            aliases = group_obj.get('aliases', [])
            
            # Combine searchable text
            searchable_text = f"{name} {description} {' '.join(aliases)}"
            
            if not case_sensitive:
                searchable_text = searchable_text.lower()
                keywords = [k.lower() for k in keywords]
            
            # Check if any keyword matches
            if any(keyword in searchable_text for keyword in keywords):
                matching_groups.append((group_id, group_obj))
                self.logger.debug(f"Group matched: {name} ({group_id})")
        
        self.logger.info(f"Found {len(matching_groups)} matching groups")
        self.logger.log_operation_end(
            "search_groups",
            True,
            {"matched_groups": len(matching_groups)}
        )
        
        return matching_groups
    
    def get_techniques_for_groups(
        self,
        group_ids: List[str],
        include_subtechniques: bool = True
    ) -> Dict[str, int]:
        """
        Get all techniques used by specified groups with counts.
        
        Args:
            group_ids: List of group IDs (STIX IDs like 'intrusion-set--xxx')
            include_subtechniques: Whether to include sub-techniques
            
        Returns:
            Dict mapping technique IDs to usage counts
        """
        self.logger.log_operation_start(
            "get_techniques_for_groups",
            {"group_count": len(group_ids), "include_subtechniques": include_subtechniques}
        )
        
        technique_counts: Dict[str, int] = {}
        
        # Convert list to set for faster lookup
        group_id_set = set(group_ids)
        
        # Debug: log some group IDs
        if group_ids:
            self.logger.debug(f"Looking for techniques from groups: {group_ids[:3]}...")
        
        for relationship in self.relationships:
            # Only look at "uses" relationships
            if relationship.get('relationship_type') != 'uses':
                continue
            
            source_ref = relationship.get('source_ref')
            target_ref = relationship.get('target_ref')
            
            # Check if source is one of our groups
            if source_ref not in group_id_set:
                continue
            
            # Check if target is an attack-pattern (technique)
            if not target_ref or not target_ref.startswith('attack-pattern--'):
                continue
            
            # Get the technique object using STIX ID
            technique_obj = self.techniques.get(target_ref)
            if not technique_obj:
                self.logger.debug(f"Technique not found: {target_ref}")
                continue
            
            # Skip deprecated/revoked
            if technique_obj.get('revoked') or technique_obj.get('x_mitre_deprecated'):
                continue
            
            # Extract the technique ID (T1234 format)
            tech_id = self._extract_technique_id(technique_obj)
            if not tech_id:
                self.logger.debug(f"Could not extract technique ID from: {target_ref}")
                continue
            
            # Filter sub-techniques if requested
            if not include_subtechniques and '.' in tech_id:
                continue
            
            technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
        
        self.logger.info(f"Found {len(technique_counts)} unique techniques")
        
        # Debug: show some techniques found
        if technique_counts:
            sample_techs = list(technique_counts.items())[:5]
            self.logger.debug(f"Sample techniques: {sample_techs}")
        
        self.logger.log_operation_end(
            "get_techniques_for_groups",
            True,
            {"unique_techniques": len(technique_counts)}
        )
        
        return technique_counts
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """
        Get details for a specific technique.
        
        Args:
            technique_id: Technique ID (e.g., "T1059") or STIX ID
            
        Returns:
            Technique object or None
        """
        # If it's a STIX ID, return directly
        if technique_id.startswith('attack-pattern--'):
            return self.techniques.get(technique_id)
        
        # Otherwise search by technique ID
        for stix_id, tech_obj in self.techniques.items():
            if self._extract_technique_id(tech_obj) == technique_id:
                return tech_obj
        return None
