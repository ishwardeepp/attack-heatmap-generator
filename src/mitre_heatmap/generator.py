"""
Core heatmap generation module.
Handles technique aggregation, scoring, and layer creation.
"""

import math
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict

from .config import (
    HeatmapConfig, 
    ScoringAlgorithm, 
    ColorScheme,
    COLOR_GRADIENTS,
    PLATFORM_MAPPINGS
)
from .data_handler import AttackDataHandler
from .logger import get_logger


class TechniqueScorer:
    """Handles different scoring algorithms for techniques."""
    
    def __init__(self, algorithm: ScoringAlgorithm, custom_weights: Optional[Dict[str, float]] = None):
        """
        Initialize scorer.
        
        Args:
            algorithm: Scoring algorithm to use
            custom_weights: Custom weights for weighted algorithm
        """
        self.algorithm = algorithm
        self.custom_weights = custom_weights or {}
        self.logger = get_logger()
    
    def score(self, technique_counts: Dict[str, int]) -> Dict[str, float]:
        """
        Apply scoring algorithm to technique counts.
        
        Args:
            technique_counts: Dict mapping technique IDs to raw counts
            
        Returns:
            Dict mapping technique IDs to scores
        """
        self.logger.log_operation_start(
            "score_techniques",
            {"algorithm": self.algorithm.value, "technique_count": len(technique_counts)}
        )
        
        if self.algorithm == ScoringAlgorithm.LINEAR:
            scores = self._linear_score(technique_counts)
        elif self.algorithm == ScoringAlgorithm.LOGARITHMIC:
            scores = self._logarithmic_score(technique_counts)
        elif self.algorithm == ScoringAlgorithm.WEIGHTED:
            scores = self._weighted_score(technique_counts)
        elif self.algorithm == ScoringAlgorithm.NORMALIZED:
            scores = self._normalized_score(technique_counts)
        else:
            self.logger.warning(f"Unknown algorithm: {self.algorithm}, using linear")
            scores = self._linear_score(technique_counts)
        
        self.logger.log_operation_end(
            "score_techniques",
            True,
            {
                "scored_techniques": len(scores),
                "min_score": min(scores.values()) if scores else 0,
                "max_score": max(scores.values()) if scores else 0,
                "avg_score": sum(scores.values()) / len(scores) if scores else 0
            }
        )
        
        return scores
    
    def _linear_score(self, technique_counts: Dict[str, int]) -> Dict[str, float]:
        """Linear scoring: score = count."""
        return {tech: float(count) for tech, count in technique_counts.items()}
    
    def _logarithmic_score(self, technique_counts: Dict[str, int]) -> Dict[str, float]:
        """Logarithmic scoring: score = log(count + 1)."""
        return {
            tech: math.log(count + 1) 
            for tech, count in technique_counts.items()
        }
    
    def _weighted_score(self, technique_counts: Dict[str, int]) -> Dict[str, float]:
        """Weighted scoring: score = count * weight."""
        scores = {}
        for tech, count in technique_counts.items():
            weight = self.custom_weights.get(tech, 1.0)
            scores[tech] = count * weight
        return scores
    
    def _normalized_score(self, technique_counts: Dict[str, int]) -> Dict[str, float]:
        """Normalized scoring: score on 0-100 scale."""
        if not technique_counts:
            return {}
        
        max_count = max(technique_counts.values())
        if max_count == 0:
            return {tech: 0.0 for tech in technique_counts}
        
        return {
            tech: (count / max_count) * 100 
            for tech, count in technique_counts.items()
        }


class HeatmapGenerator:
    """
    Main heatmap generator class.
    Orchestrates data loading, scoring, and layer generation.
    """
    
    def __init__(self, config: HeatmapConfig):
        """
        Initialize generator.
        
        Args:
            config: HeatmapConfig instance
        """
        self.config = config
        self.logger = get_logger()
        self.data_handler = AttackDataHandler(config.attack, config.cache)
        self.scorer = TechniqueScorer(config.scoring_algorithm, config.custom_weights)
        
        self.technique_scores: Dict[str, float] = {}
        self.metadata: Dict[str, any] = {}
    
    def generate_from_groups(
        self,
        group_search_terms: List[str]
    ) -> bool:
        """
        Generate heatmap from threat group search.
        
        Args:
            group_search_terms: Keywords to search for groups
            
        Returns:
            True if successful
        """
        self.logger.log_operation_start(
            "generate_from_groups",
            {"search_terms": group_search_terms}
        )
        
        # Load ATT&CK data
        if not self.data_handler.load_attack_data(self.config.matrix_type):
            self.logger.error("Failed to load ATT&CK data")
            return False
        
        # Search for groups
        if '*' in group_search_terms or group_search_terms == ['*']:
            # Use all groups
            matching_groups = list(self.data_handler.groups.items())
            self.logger.info("Using all threat groups (wildcard)")
        else:
            matching_groups = self.data_handler.search_groups_by_keywords(group_search_terms)
        
        if not matching_groups:
            self.logger.warning("No matching groups found")
            return False
        
        group_ids = [gid for gid, _ in matching_groups]
        group_names = [gobj.get('name', 'Unknown') for _, gobj in matching_groups]
        
        self.logger.info(f"Found {len(matching_groups)} matching groups: {', '.join(group_names[:10])}")
        if len(group_names) > 10:
            self.logger.info(f"... and {len(group_names) - 10} more")
        
        # Get techniques
        technique_counts = self.data_handler.get_techniques_for_groups(
            group_ids,
            include_subtechniques=True
        )
        
        if not technique_counts:
            self.logger.warning("No techniques found for matched groups")
            return False
        
        # Merge sub-techniques to parent if configured
        if self.config.merge_subtechniques:
            technique_counts = self._merge_subtechniques(technique_counts)
        
        # Apply platform filter
        if self.config.platforms:
            technique_counts = self._filter_by_platform(technique_counts)
        
        # Apply threshold
        if self.config.threshold > 0:
            technique_counts = self._apply_threshold(technique_counts)
        
        # Score techniques
        self.technique_scores = self.scorer.score(technique_counts)
        
        # Store metadata
        self.metadata = {
            'search_terms': group_search_terms,
            'matched_groups': group_names,
            'total_techniques': len(self.technique_scores),
            'matrix_type': self.config.matrix_type.value,
        }
        
        self.logger.log_operation_end(
            "generate_from_groups",
            True,
            {
                "groups": len(matching_groups),
                "techniques": len(self.technique_scores)
            }
        )
        
        return True
    
    def generate_from_technique_list(
        self,
        technique_ids: List[str],
        default_score: float = 1.0
    ) -> bool:
        """
        Generate heatmap from explicit technique list.
        
        Args:
            technique_ids: List of technique IDs
            default_score: Default score for each technique
            
        Returns:
            True if successful
        """
        self.logger.log_operation_start(
            "generate_from_technique_list",
            {"technique_count": len(technique_ids)}
        )
        
        # Load ATT&CK data (needed for validation and details)
        if not self.data_handler.load_attack_data(self.config.matrix_type):
            self.logger.error("Failed to load ATT&CK data")
            return False
        
        # Count occurrences
        technique_counts = defaultdict(int)
        for tech_id in technique_ids:
            technique_counts[tech_id.upper()] += 1
        
        self.logger.info(f"Processed {len(technique_counts)} unique techniques")
        
        # Merge sub-techniques if configured
        if self.config.merge_subtechniques:
            technique_counts = self._merge_subtechniques(dict(technique_counts))
        
        # Apply platform filter
        if self.config.platforms:
            technique_counts = self._filter_by_platform(technique_counts)
        
        # Apply threshold
        if self.config.threshold > 0:
            technique_counts = self._apply_threshold(technique_counts)
        
        # Score techniques
        self.technique_scores = self.scorer.score(technique_counts)
        
        # Store metadata
        self.metadata = {
            'input_type': 'technique_list',
            'total_techniques': len(self.technique_scores),
            'matrix_type': self.config.matrix_type.value,
        }
        
        self.logger.log_operation_end(
            "generate_from_technique_list",
            True,
            {"techniques": len(self.technique_scores)}
        )
        
        return True
    
    def _merge_subtechniques(self, technique_counts: Dict[str, int]) -> Dict[str, int]:
        """
        Propagate sub-technique counts to parent techniques.
        
        Args:
            technique_counts: Original technique counts
            
        Returns:
            Updated technique counts with merged sub-techniques
        """
        self.logger.debug("Merging sub-technique scores to parent techniques")
        
        merged = technique_counts.copy()
        
        for tech_id, count in technique_counts.items():
            if '.' in tech_id:
                # This is a sub-technique
                parent_id = tech_id.split('.')[0]
                merged[parent_id] = merged.get(parent_id, 0) + count
                self.logger.debug(f"Merged {tech_id} ({count}) to parent {parent_id}")
        
        return merged
    
    def _filter_by_platform(self, technique_counts: Dict[str, int]) -> Dict[str, int]:
        """
        Filter techniques by platform.
        
        Args:
            technique_counts: Technique counts to filter
            
        Returns:
            Filtered technique counts
        """
        self.logger.debug(f"Filtering by platforms: {self.config.platforms}")
        
        filtered = {}
        
        # Get allowed platforms
        allowed_platforms = set()
        for platform_key in self.config.platforms:
            platform_values = PLATFORM_MAPPINGS.get(platform_key.lower())
            if platform_values:
                allowed_platforms.update(platform_values)
        
        if not allowed_platforms:
            self.logger.warning("No valid platforms specified, skipping filter")
            return technique_counts
        
        # Filter techniques
        for tech_id, count in technique_counts.items():
            tech_obj = self.data_handler.get_technique_details(tech_id)
            if not tech_obj:
                # If we can't find details, include it
                filtered[tech_id] = count
                continue
            
            tech_platforms = tech_obj.get('x_mitre_platforms', [])
            
            # Check if any platform matches
            if any(plat in allowed_platforms for plat in tech_platforms):
                filtered[tech_id] = count
                self.logger.debug(f"Included {tech_id} (platforms: {tech_platforms})")
            else:
                self.logger.debug(f"Filtered out {tech_id} (platforms: {tech_platforms})")
        
        self.logger.info(f"Platform filter: {len(technique_counts)} -> {len(filtered)} techniques")
        
        return filtered
    
    def _apply_threshold(self, technique_counts: Dict[str, int]) -> Dict[str, int]:
        """
        Apply threshold filtering.
        
        Args:
            technique_counts: Technique counts to filter
            
        Returns:
            Filtered technique counts
        """
        self.logger.debug(f"Applying threshold: {self.config.threshold}")
        
        filtered = {}
        
        for tech_id, count in technique_counts.items():
            # Always keep sub-techniques
            if '.' in tech_id:
                filtered[tech_id] = count
            # Filter parent techniques by threshold
            elif count >= self.config.threshold:
                filtered[tech_id] = count
            else:
                self.logger.debug(f"Filtered out {tech_id} (count: {count} < {self.config.threshold})")
        
        self.logger.info(f"Threshold filter: {len(technique_counts)} -> {len(filtered)} techniques")
        
        return filtered
    
    def get_navigator_layer(self) -> Dict:
        """
        Generate ATT&CK Navigator layer JSON.
        
        Returns:
            Navigator layer dictionary
        """
        self.logger.log_operation_start("generate_navigator_layer")
        
        if not self.technique_scores:
            self.logger.error("No technique scores available. Generate heatmap first.")
            return {}
        
        # Get color gradient
        gradient = COLOR_GRADIENTS.get(
            self.config.color_scheme,
            COLOR_GRADIENTS[ColorScheme.RED_YELLOW_GREEN]
        )
        
        # Build technique objects for layer
        techniques = []
        for tech_id, score in self.technique_scores.items():
            tech_obj = {
                'techniqueID': tech_id,
                'score': score,
                'enabled': True,
                'comment': f'Score: {score:.2f}'
            }
            techniques.append(tech_obj)
        
        # Build layer
        layer = {
            'name': self.config.title,
            'versions': {
                'attack': '17',  # Will be updated dynamically in future
                'navigator': '5.2.0',
                'layer': '4.5'
            },
            'domain': self.config.matrix_type.value,
            'description': self.config.description or 'Generated heatmap',
            'filters': {
                'platforms': self.config.platforms or []
            },
            'sorting': 3,  # Sort by score descending
            'layout': {
                'layout': 'side',
                'aggregateFunction': 'average',
                'showID': False,
                'showName': True,
                'showAggregateScores': False,
                'countUnscored': False
            },
            'hideDisabled': False,
            'techniques': techniques,
            'gradient': {
                'colors': [
                    gradient['minColor'],
                    gradient['midColor'],
                    gradient['maxColor']
                ],
                'minValue': min(self.technique_scores.values()) if self.technique_scores else 0,
                'maxValue': max(self.technique_scores.values()) if self.technique_scores else 100
            },
            'legendItems': [],
            'metadata': [
                {'name': 'Generated by', 'value': 'MITRE ATT&CK Heatmap Generator Pro'},
                {'name': 'Matrix', 'value': self.config.matrix_type.value},
                {'name': 'Techniques', 'value': str(len(self.technique_scores))}
            ],
            'links': [],
            'showTacticRowBackground': True,
            'tacticRowBackground': '#dddddd',
            'selectTechniquesAcrossTactics': True,
            'selectSubtechniquesWithParent': True
        }
        
        # Add metadata
        if self.metadata:
            for key, value in self.metadata.items():
                if key != 'matrix_type':  # Already added
                    layer['metadata'].append({
                        'name': key.replace('_', ' ').title(),
                        'value': str(value) if not isinstance(value, list) else ', '.join(value[:5])
                    })
        
        self.logger.log_operation_end(
            "generate_navigator_layer",
            True,
            {"techniques": len(techniques)}
        )
        
        return layer
    
    def get_statistics(self) -> Dict:
        """
        Get statistics about the generated heatmap.
        
        Returns:
            Dictionary of statistics
        """
        if not self.technique_scores:
            return {}
        
        scores = list(self.technique_scores.values())
        
        stats = {
            'total_techniques': len(self.technique_scores),
            'min_score': min(scores),
            'max_score': max(scores),
            'mean_score': sum(scores) / len(scores),
            'median_score': sorted(scores)[len(scores) // 2],
            'parent_techniques': sum(1 for t in self.technique_scores if '.' not in t),
            'sub_techniques': sum(1 for t in self.technique_scores if '.' in t),
        }
        
        # Add metadata
        stats.update(self.metadata)
        
        return stats
