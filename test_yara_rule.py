#!/usr/bin/env python3
"""
Comprehensive test suite for the YARA rule against obfuscation techniques.

This script tests the YARA rule against two types of test cases:
1. Code-based obfuscation (functions, techniques)
2. Text-based obfuscation (actual obfuscated text outcomes)
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
        has_match = bool(result.stdout.strip() and not result.stdout.strip().startswith('warning:'))
        return has_match, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except FileNotFoundError:
        return False, "", "YARA not found - please install YARA"
    except Exception as e:
        return False, "", str(e)

def run_test_suite(test_suite_name, test_cases, debug_mode=False):
    """Run a specific test suite and return results"""
    rule_file = "LLM_Malware_Detection.yar"
    test_dir = Path("test_files")
    
    print(f"\n🔍 {test_suite_name}")
    print("=" * 70)
    
    results = []
    
    for test_file, expected, description in test_cases:
        test_path = test_dir / test_file
        
        if not test_path.exists():
            print(f"⚠️  Test file not found: {test_path}")
            continue
            
        matched, stdout, stderr = run_yara_test(rule_file, str(test_path))
        
        if matched == expected:
            status = "✅ PASS"
            results.append(True)
        else:
            status = "❌ FAIL"
            results.append(False)
            
        print(f"{status} | {test_file:<35} | Expected: {expected:<5} | Got: {matched:<5} | {description}")
        
        # Show details for failed tests or in debug mode
        if matched != expected or debug_mode:
            if stderr and stderr.strip():
                print(f"      Error: {stderr.strip()}")
            if stdout and stdout.strip():
                print(f"      Match: {stdout.strip()}")
            elif not matched:
                print(f"      Debug: No match found")
    
    return results

def main():
    """Main validation function"""
    rule_file = "LLM_Malware_Detection.yar"
    test_dir = Path("test_files")
    
    # Check for debug mode
    debug_mode = "--debug" in sys.argv or "-d" in sys.argv
    
    if not os.path.exists(rule_file):
        print(f"❌ Rule file not found: {rule_file}")
        return 1
        
    if not test_dir.exists():
        print(f"❌ Test directory not found: {test_dir}")
        return 1
    
    print("🔍 Testing YARA Rule: Advanced_Text_Obfuscation_Detection")
    print(f"Debug mode: {'ON' if debug_mode else 'OFF'}")
    
    # Test Suite 1: Code-based obfuscation patterns
    code_test_cases = [
        # Should trigger (positive tests) - obfuscation code/functions
        ("test_unicode_obfuscation.txt", True, "Unicode obfuscation patterns"),
        ("test_steganography.txt", True, "Steganographic techniques"),
        ("test_encoding_patterns.txt", True, "Multiple encoding patterns"),
        ("test_obfuscation_code.py", True, "Obfuscation functions"),
        ("test_combined_techniques.txt", True, "Combined techniques"),
        
        # Should NOT trigger (negative tests)
        ("test_negative_simple.txt", False, "Plain text"),
        ("test_minimal_obfuscation.txt", False, "Minimal obfuscation below threshold"),
    ]
    
    # Test Suite 2: Actual obfuscated text outcomes
    text_test_cases = [
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
        ("moar_zalgo.txt", True, "More zalgo text"),
        
        # New comprehensive test files
        ("test_special_techniques.txt", True, "Special techniques: Elder Futhark, Medieval, Cursive, etc."),
        ("test_unicode_comprehensive.txt", True, "Unicode: Invisible, Upside Down, Small Caps, Braille, etc."),
        ("test_visual_formatting.txt", True, "Visual: Strikethrough, Underline, Rainbow, Leetspeak, NATO, Pig Latin"),
        ("test_ciphers_comprehensive.txt", True, "Ciphers: Morse, ROT13, ROT47, Binary, Hex, Base64, etc."),
        ("test_zalgo_comprehensive.txt", True, "Comprehensive zalgo corruption text"),
        
        # Should NOT trigger (negative tests)
        ("test_no_obfuscation.txt", False, "Plain text with no obfuscation"),
        ("test_false_positive_check.txt", False, "False positive check - similar but not obfuscated"),
        ("test_edge_cases.txt", False, "Edge cases - minimal content below thresholds"),
        ("test_negative_comprehensive.txt", False, "Comprehensive negative test - plain text only"),
    ]
    
    # Run both test suites
    code_results = run_test_suite(
        "Test Suite 1: Code-based Obfuscation Detection", 
        code_test_cases, 
        debug_mode
    )
    
    text_results = run_test_suite(
        "Test Suite 2: Actual Obfuscated Text Detection", 
        text_test_cases, 
        debug_mode
    )
    
    # Combined summary
    all_results = code_results + text_results
    passed = sum(all_results)
    total = len(all_results)
    success_rate = (passed / total * 100) if total > 0 else 0
    
    print("\n" + "=" * 70)
    print(f"📊 Overall Test Results: {passed}/{total} passed ({success_rate:.1f}%)")
    print(f"   Code-based tests: {sum(code_results)}/{len(code_results)} passed")
    print(f"   Text-based tests: {sum(text_results)}/{len(text_results)} passed")
    
    if passed == total:
        print("🎉 All tests passed! YARA rule is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the rule logic.")
        return 1

if __name__ == "__main__":
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: python test_yara_rule.py [--debug|-d] [--help|-h]")
        print("  --debug, -d: Show detailed output for all tests")
        print("  --help, -h:  Show this help message")
        sys.exit(0)
    
    exit(main())
