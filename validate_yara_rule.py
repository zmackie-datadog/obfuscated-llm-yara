#!/usr/bin/env python3
"""
Validation script to test the YARA rule against test files
"""

import subprocess
import os
import sys
from pathlib import Path

def run_yara_test(rule_file, test_file):
    """Run YARA against a single test file"""
    try:
        result = subprocess.run(
            ['yara', rule_file, test_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        # YARA returns 0 for both success and no matches
        # Check if there's actual match output to determine if a rule matched
        has_match = bool(result.stdout.strip() and not result.stdout.strip().startswith('warning:'))
        return has_match, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except FileNotFoundError:
        return False, "", "YARA not found - please install YARA"
    except Exception as e:
        return False, "", str(e)

def main():
    """Main validation function"""
    rule_file = "LLM_Malware_Detection.yar"
    test_dir = Path("test_files")
    
    if not os.path.exists(rule_file):
        print(f"❌ Rule file not found: {rule_file}")
        return 1
        
    if not test_dir.exists():
        print(f"❌ Test directory not found: {test_dir}")
        return 1
    
    print("🔍 Testing YARA Rule: Advanced_Text_Obfuscation_Detection")
    print("=" * 60)
    
    # Test cases with expected results
    test_cases = [
        # Should trigger (positive tests)
        ("test_unicode_obfuscation.txt", True, "Unicode obfuscation patterns"),
        ("test_steganography.txt", True, "Steganographic techniques"),
        ("test_encoding_patterns.txt", True, "Multiple encoding patterns"),
        ("test_obfuscation_code.py", True, "Obfuscation functions"),
        ("test_combined_techniques.txt", True, "Combined techniques"),
        
        # Should NOT trigger (negative tests)
        ("test_negative_simple.txt", False, "Plain text"),
        ("test_minimal_obfuscation.txt", False, "Minimal obfuscation below threshold"),
    ]
    
    results = []
    
    for test_file, expected, description in test_cases:
        test_path = test_dir / test_file
        
        if not test_path.exists():
            print(f"⚠️  Test file not found: {test_path}")
            continue
            
        matched, stdout, stderr = run_yara_test(rule_file, str(test_path))
        
        # Determine if test passed
        if matched == expected:
            status = "✅ PASS"
            results.append(True)
        else:
            status = "❌ FAIL"
            results.append(False)
            
        print(f"{status} | {test_file:<30} | Expected: {expected:<5} | Got: {matched:<5} | {description}")
        
        # Show YARA output for failed tests or debug info
        if stderr and stderr.strip():
            print(f"      Error: {stderr.strip()}")
        if stdout and stdout.strip():
            print(f"      Match: {stdout.strip()}")
        
        # Debug: show what YARA actually returned
        print(f"      Debug: returncode={matched}, stdout='{stdout.strip()}', stderr='{stderr.strip()}'")
    
    print("=" * 60)
    
    # Summary
    passed = sum(results)
    total = len(results)
    success_rate = (passed / total * 100) if total > 0 else 0
    
    print(f"📊 Test Results: {passed}/{total} passed ({success_rate:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! YARA rule is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the rule logic.")
        return 1

if __name__ == "__main__":
    exit(main())
