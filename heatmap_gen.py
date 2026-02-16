#!/usr/bin/env python3
"""
MITRE ATT&CK Heatmap Generator - Professional Edition
Main CLI application
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from mitre_heatmap.config import (
    HeatmapConfig,
    MatrixType,
    ScoringAlgorithm,
    ColorScheme,
    InputFormat,
    ExportFormat
)
from mitre_heatmap.logger import setup_logging, get_logger
from mitre_heatmap.validator import Validator
from mitre_heatmap.generator import HeatmapGenerator
from mitre_heatmap.parsers import InputParserFactory


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description='MITRE ATT&CK Heatmap Generator - Professional Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate from threat group keywords
  %(prog)s groups -s energy financial -o energy_threats -t "Energy Sector Threats"
  
  # Generate from technique list file
  %(prog)s techniques -i techniques.json -o my_heatmap -t "My Techniques"
  
  # Generate from CSV file
  %(prog)s techniques -i report.csv -o analysis -t "Threat Analysis"
  
  # Extract from text report
  %(prog)s text -i threat_report.txt -o extracted -t "Extracted TTPs"
  
  # Use all threat groups with threshold
  %(prog)s groups -s "*" --threshold 5 -o common_techniques -t "Common Techniques"
  
  # Custom configuration
  %(prog)s groups -s healthcare --matrix mobile --scoring logarithmic -o mobile_healthcare
        """
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Generation mode')
    
    # Group-based generation
    group_parser = subparsers.add_parser(
        'groups',
        help='Generate heatmap from threat group keywords'
    )
    group_parser.add_argument(
        '-s', '--search',
        nargs='+',
        required=True,
        help='Search terms for threat groups (use "*" for all groups)'
    )
    
    # Technique-based generation
    tech_parser = subparsers.add_parser(
        'techniques',
        help='Generate heatmap from technique list file'
    )
    tech_parser.add_argument(
        '-i', '--input',
        required=True,
        help='Input file (JSON, CSV, or STIX bundle)'
    )
    tech_parser.add_argument(
        '--format',
        choices=['auto', 'json', 'csv', 'stix'],
        default='auto',
        help='Input file format (default: auto-detect)'
    )
    tech_parser.add_argument(
        '--csv-column',
        help='CSV column name containing technique IDs'
    )
    
    # Text extraction generation
    text_parser = subparsers.add_parser(
        'text',
        help='Generate heatmap by extracting technique IDs from text'
    )
    text_parser.add_argument(
        '-i', '--input',
        required=True,
        help='Text file to extract techniques from'
    )
    
    # Common arguments for all subcommands
    for subparser in [group_parser, tech_parser, text_parser]:
        subparser.add_argument(
            '-o', '--output',
            required=True,
            help='Output filename (without extension)'
        )
        subparser.add_argument(
            '-t', '--title',
            required=True,
            help='Heatmap title'
        )
        subparser.add_argument(
            '--description',
            default='',
            help='Heatmap description'
        )
        subparser.add_argument(
            '--matrix',
            choices=['enterprise', 'mobile', 'ics'],
            default='enterprise',
            help='ATT&CK matrix type (default: enterprise)'
        )
        subparser.add_argument(
            '--threshold',
            type=int,
            default=0,
            help='Minimum score threshold for parent techniques (default: 0)'
        )
        subparser.add_argument(
            '--no-merge',
            action='store_true',
            help='Do not merge sub-technique scores to parent techniques'
        )
        subparser.add_argument(
            '--scoring',
            choices=['linear', 'logarithmic', 'weighted', 'normalized'],
            default='linear',
            help='Scoring algorithm (default: linear)'
        )
        subparser.add_argument(
            '--color-scheme',
            choices=['red_yellow_green', 'blue_white_red', 'viridis', 'plasma'],
            default='red_yellow_green',
            help='Color scheme (default: red_yellow_green)'
        )
        subparser.add_argument(
            '--platforms',
            nargs='+',
            help='Filter by platforms (e.g., windows linux macos)'
        )
        subparser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            default='INFO',
            help='Logging level (default: INFO)'
        )
        subparser.add_argument(
            '--log-file',
            help='Log to file'
        )
        subparser.add_argument(
            '--no-cache',
            action='store_true',
            help='Disable caching of ATT&CK data'
        )
        subparser.add_argument(
            '--export-stats',
            action='store_true',
            help='Export statistics JSON file'
        )
    
    return parser


def map_matrix_type(matrix_str: str) -> MatrixType:
    """Map string to MatrixType enum."""
    mapping = {
        'enterprise': MatrixType.ENTERPRISE,
        'mobile': MatrixType.MOBILE,
        'ics': MatrixType.ICS
    }
    return mapping.get(matrix_str, MatrixType.ENTERPRISE)


def map_scoring_algorithm(scoring_str: str) -> ScoringAlgorithm:
    """Map string to ScoringAlgorithm enum."""
    mapping = {
        'linear': ScoringAlgorithm.LINEAR,
        'logarithmic': ScoringAlgorithm.LOGARITHMIC,
        'weighted': ScoringAlgorithm.WEIGHTED,
        'normalized': ScoringAlgorithm.NORMALIZED
    }
    return mapping.get(scoring_str, ScoringAlgorithm.LINEAR)


def map_color_scheme(color_str: str) -> ColorScheme:
    """Map string to ColorScheme enum."""
    mapping = {
        'red_yellow_green': ColorScheme.RED_YELLOW_GREEN,
        'blue_white_red': ColorScheme.BLUE_WHITE_RED,
        'viridis': ColorScheme.VIRIDIS,
        'plasma': ColorScheme.PLASMA
    }
    return mapping.get(color_str, ColorScheme.RED_YELLOW_GREEN)


def detect_input_format(file_path: str, format_arg: str) -> InputFormat:
    """Detect input format from file extension."""
    if format_arg != 'auto':
        format_map = {
            'json': InputFormat.JSON_FILE,
            'csv': InputFormat.CSV_FILE,
            'stix': InputFormat.STIX_BUNDLE
        }
        return format_map.get(format_arg, InputFormat.JSON_FILE)
    
    # Auto-detect
    path = Path(file_path)
    suffix = path.suffix.lower()
    
    if suffix == '.json':
        # Try to determine if it's STIX
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get('type') == 'bundle':
                return InputFormat.STIX_BUNDLE
        except:
            pass
        return InputFormat.JSON_FILE
    elif suffix in ['.csv', '.tsv']:
        return InputFormat.CSV_FILE
    else:
        return InputFormat.JSON_FILE


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Build configuration
    config = HeatmapConfig()
    config.title = args.title
    config.description = args.description
    config.matrix_type = map_matrix_type(args.matrix)
    config.threshold = args.threshold
    config.merge_subtechniques = not args.no_merge
    config.scoring_algorithm = map_scoring_algorithm(args.scoring)
    config.color_scheme = map_color_scheme(args.color_scheme)
    config.platforms = args.platforms
    config.logging.level = args.log_level
    config.logging.file_path = args.log_file
    config.cache.enabled = not args.no_cache
    
    # Setup logging
    logger = setup_logging(config.logging)
    logger.info("=" * 70)
    logger.info("MITRE ATT&CK Heatmap Generator - Professional Edition")
    logger.info("=" * 70)
    logger.set_context(command=args.command, output=args.output)
    
    try:
        # Validate configuration
        validator = Validator(config.validation)
        config_result = validator.validate_config(config)
        
        if not config_result.is_valid:
            logger.error("Configuration validation failed:")
            for error in config_result.errors:
                logger.error(f"  - {error}")
            sys.exit(1)
        
        if config_result.warnings:
            for warning in config_result.warnings:
                logger.warning(warning)
        
        # Create generator
        generator = HeatmapGenerator(config)
        
        # Generate heatmap based on command
        success = False
        
        if args.command == 'groups':
            logger.info(f"Generating heatmap from threat groups: {args.search}")
            success = generator.generate_from_groups(args.search)
            
        elif args.command == 'techniques':
            logger.info(f"Generating heatmap from file: {args.input}")
            
            # Parse input file
            input_format = detect_input_format(args.input, args.format)
            logger.info(f"Detected format: {input_format.value}")
            
            parser_instance = InputParserFactory.create_parser(input_format, validator)
            
            if input_format == InputFormat.CSV_FILE:
                parse_result = parser_instance.parse(args.input, args.csv_column)
            else:
                parse_result = parser_instance.parse(args.input)
            
            if not parse_result.is_valid:
                logger.error("Input parsing failed:")
                for error in parse_result.errors:
                    logger.error(f"  - {error}")
                sys.exit(1)
            
            if parse_result.warnings:
                for warning in parse_result.warnings:
                    logger.warning(warning)
            
            # Generate from parsed techniques
            success = generator.generate_from_technique_list(parse_result.sanitized_value)
            
        elif args.command == 'text':
            logger.info(f"Extracting techniques from: {args.input}")
            
            # Parse text file
            text_parser = InputParserFactory.create_parser(
                InputFormat.TEXT_EXTRACTION,
                validator
            )
            parse_result = text_parser.parse_file(args.input)
            
            if not parse_result.is_valid:
                logger.error("Text extraction failed:")
                for error in parse_result.errors:
                    logger.error(f"  - {error}")
                sys.exit(1)
            
            logger.info(f"Extracted {len(parse_result.sanitized_value)} techniques")
            
            # Generate from extracted techniques
            success = generator.generate_from_technique_list(parse_result.sanitized_value)
        
        if not success:
            logger.error("Heatmap generation failed")
            sys.exit(1)
        
        # Generate Navigator layer
        layer = generator.get_navigator_layer()
        
        if not layer:
            logger.error("Failed to generate Navigator layer")
            sys.exit(1)
        
        # Save output
        output_path = Path(config.output_directory) / f"{args.output}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(layer, f, indent=2)
        
        logger.info(f"Heatmap saved to: {output_path}")
        
        # Export statistics if requested
        if args.export_stats:
            stats = generator.get_statistics()
            stats_path = Path(config.output_directory) / f"{args.output}_stats.json"
            
            with open(stats_path, 'w') as f:
                json.dump(stats, f, indent=2)
            
            logger.info(f"Statistics saved to: {stats_path}")
        
        # Print summary
        stats = generator.get_statistics()
        logger.info("-" * 70)
        logger.info("Generation Summary:")
        logger.info(f"  Total Techniques: {stats.get('total_techniques', 0)}")
        logger.info(f"  Parent Techniques: {stats.get('parent_techniques', 0)}")
        logger.info(f"  Sub-techniques: {stats.get('sub_techniques', 0)}")
        logger.info(f"  Score Range: {stats.get('min_score', 0):.2f} - {stats.get('max_score', 0):.2f}")
        logger.info(f"  Mean Score: {stats.get('mean_score', 0):.2f}")
        
        if 'matched_groups' in stats:
            group_list = stats['matched_groups']
            logger.info(f"  Threat Groups: {len(group_list)}")
            if len(group_list) <= 10:
                logger.info(f"    {', '.join(group_list)}")
            else:
                logger.info(f"    {', '.join(group_list[:10])} ... and {len(group_list)-10} more")
        
        logger.info("-" * 70)
        logger.info("SUCCESS! Open the layer in ATT&CK Navigator:")
        logger.info("  https://mitre-attack.github.io/attack-navigator/")
        logger.info("=" * 70)
        
        # Get and print metrics
        metrics = logger.get_metrics()
        if metrics:
            logger.debug("Metrics:")
            for key, value in metrics.items():
                logger.debug(f"  {key}: {value}")
        
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(130)
    
    except Exception as e:
        logger.critical(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
