#!/usr/bin/env python3
"""
Test runner script for MITRE ATT&CK Heatmap Generator.
Runs all tests with detailed output and coverage reporting.
"""

import sys
import subprocess
from pathlib import Path


def run_tests():
    """Run all tests with pytest."""
    print("=" * 70)
    print("MITRE ATT&CK Heatmap Generator - Test Suite")
    print("=" * 70)
    print()
    
    # Change to project root
    project_root = Path(__file__).parent
    
    # Run tests with coverage
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(project_root / "tests"),
        "-v",
        "--tb=short",
        "--color=yes",
        "-ra",  # Show all test results
    ]
    
    print(f"Running: {' '.join(cmd)}")
    print()
    
    result = subprocess.run(cmd, cwd=project_root)
    
    print()
    print("=" * 70)
    
    if result.returncode == 0:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed!")
    
    print("=" * 70)
    
    return result.returncode


def run_tests_with_coverage():
    """Run tests with coverage report."""
    print("=" * 70)
    print("MITRE ATT&CK Heatmap Generator - Test Suite with Coverage")
    print("=" * 70)
    print()
    
    project_root = Path(__file__).parent
    
    # Run tests with coverage
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(project_root / "tests"),
        "-v",
        "--tb=short",
        "--color=yes",
        "--cov=src/mitre_heatmap",
        "--cov-report=term-missing",
        "--cov-report=html",
        "-ra",
    ]
    
    print(f"Running: {' '.join(cmd)}")
    print()
    
    result = subprocess.run(cmd, cwd=project_root)
    
    print()
    print("=" * 70)
    
    if result.returncode == 0:
        print("✓ All tests passed!")
        print(f"✓ Coverage report generated: {project_root}/htmlcov/index.html")
    else:
        print("✗ Some tests failed!")
    
    print("=" * 70)
    
    return result.returncode


def run_specific_test(test_path: str):
    """Run a specific test."""
    project_root = Path(__file__).parent
    
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        test_path,
        "-v",
        "--tb=short",
        "--color=yes",
    ]
    
    print(f"Running: {' '.join(cmd)}")
    print()
    
    result = subprocess.run(cmd, cwd=project_root)
    
    return result.returncode


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "coverage":
            sys.exit(run_tests_with_coverage())
        else:
            # Run specific test
            sys.exit(run_specific_test(sys.argv[1]))
    else:
        sys.exit(run_tests())
