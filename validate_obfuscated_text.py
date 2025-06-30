#!/usr/bin/env python3
"""
Validation script to test the YARA rule against actual obfuscated text outcomes
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
    print("Focus: Detecting actual obfuscated text outcomes (not code)")
    print("=" * 70)
    
    # Test cases with expected results - focus on actual obfuscated text
    test_cases = [
        # Should trigger (positive tests) - actual obfuscated text
        ("test_actual_upside_down.txt", True, "Actual upside down Unicode text"),
        ("test_actual_zalgo.txt", True, "Actual zalgo corrupted text"), 
        ("test_actual_runes.txt", True, "Actual Elder Futhark runic text"),
        ("test_actual_braille.txt", True, "Actual Braille text"),
        ("test_actual_base64_outcome.txt", True, "Actual Base64 encoded strings"),
        ("test_actual_emoji_steganography.txt", True, "Actual emoji steganography"),
        ("test_actual_morse_outcome.txt", True, "Actual Morse code patterns"),
        ("test_actual_leetspeak_outcome.txt", True, "Actual leetspeak text"),
        ("test_actual_hex_outcome.txt", True, "Actual hex encoded text"),
        ("test_mixed_obfuscation_outcome.txt", True, "Mixed obfuscation outcomes"),
        
        # Should NOT trigger (negative tests)
        ("test_no_obfuscation.txt", False, "Plain text with no obfuscation"),
        ("test_minimal_obfuscation.txt", False, "Minimal obfuscation below threshold"),
        ("test_false_positive_check.txt", False, "False positive check - similar but not obfuscated"),
        ("test_edge_cases.txt", False, "Edge cases - minimal content below thresholds"),
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
            
        print(f"{status} | {test_file:<35} | Expected: {expected:<5} | Got: {matched:<5} | {description}")
        
        # Show details for failed tests
        if matched != expected:
            if stderr and stderr.strip():
                print(f"      Error: {stderr.strip()}")
            if stdout and stdout.strip():
                print(f"      Match: {stdout.strip()}")
            else:
                print(f"      Debug: No match found")
    
    print("=" * 70)
    
    # Summary
    passed = sum(results)
    total = len(results)
    success_rate = (passed / total * 100) if total > 0 else 0
    
    print(f"📊 Test Results: {passed}/{total} passed ({success_rate:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! YARA rule correctly detects obfuscated text outcomes.")
        return 0
    else:
        print("⚠️  Some tests failed. Rule needs refinement.")
        return 1

if __name__ == "__main__":
    exit(main())
