# P4RS3LT0NGV3 Obfuscation Detection Testing

This directory contains a comprehensive testing framework for detecting text obfuscation techniques used by the P4RS3LT0NGV3 application.

## Files Created

1. **`test_obfuscation_samples.txt`** - Test samples for 36 different obfuscation techniques
2. **`test_harness.py`** - Python test harness that runs Yara rules against samples
3. **`obfuscation_detection.yar`** - Comprehensive Yara rules for detection
4. **`README_TESTING.md`** - This documentation file

## Obfuscation Techniques Covered

### Encoding (7 techniques)
- Base64, Base32, Binary, Hexadecimal, ASCII85, URL Encoding, HTML Entities

### Ciphers (4 techniques)  
- Caesar Cipher, ROT13, ROT47, Morse Code

### Visual/Formatting (4 techniques)
- Rainbow Text, Strikethrough, Underline, Reverse Text

### Unicode Manipulation (8 techniques)
- Invisible Text, Upside Down, Full Width, Small Caps, Bubble, Braille, Greek Letters, Wingdings

### Special Techniques (11 techniques)
- Medieval, Cursive, Monospace, Double-Struck, Elder Futhark, Mirror Text, Zalgo, Vaporwave, Pig Latin, Leetspeak, NATO Phonetic

### Steganography (2 techniques)
- Emoji Steganography, Invisible Text Steganography

## Prerequisites

```bash
# Install required Python packages
pip install yara-python

# Ensure you have Yara installed on your system
# On macOS: brew install yara
# On Ubuntu: apt-get install yara
# On Windows: Download from https://yara.readthedocs.io/
```

## Usage

### Running the Test Harness

```bash
# Basic usage
python test_harness.py obfuscation_detection.yar test_obfuscation_samples.txt

# This will:
# 1. Load the Yara rules
# 2. Load the test samples
# 3. Run detection tests on all samples
# 4. Generate a detailed report (test_report.md)
# 5. Save results as JSON (test_results.json)
```

### Example Output

```
🚀 P4RS3LT0NGV3 Obfuscation Detection Test Harness
==================================================
✓ Loaded Yara rules from obfuscation_detection.yar
✓ Loaded 36 test samples

🧪 Running tests on 36 obfuscation techniques...
============================================================
✓ DETECTED   BASE64               | SGVsbG8gV29ybGQ=
✓ DETECTED   BASE32               | JBSWY3DPEBLW64TMMQQQ====
✓ DETECTED   BINARY               | 01001000 01100101 01101100 01101100 01101111
✗ MISSED     CAESAR_CIPHER        | Khoor Zruog
...
============================================================
Detection Rate: 28/36 (77.8%)

📄 Report saved to test_report.md
📊 JSON results saved to test_results.json
🎯 Test completed! Detection rate: 77.8%
```

## Yara Rules Structure

The Yara rules are organized into categories:

- **Individual Technique Rules**: Each obfuscation technique has its own rule
- **Combination Rules**: Detect multiple techniques used together
- **Master Detection Rule**: Catches any P4RS3LT0NGV3 technique
- **Heuristic Rules**: Detect suspicious patterns

### Key Rules

- `P4RS3LT0NGV3_Master_Detection` - Catches any obfuscation technique
- `P4RS3LT0NGV3_Multiple_Obfuscation` - Detects layered obfuscation
- `P4RS3LT0NGV3_Suspicious_Patterns` - Heuristic detection

## Customization

### Adding New Test Samples

Edit `test_obfuscation_samples.txt`:
```
NEW_TECHNIQUE: your_obfuscated_sample_here
```

### Adding New Yara Rules

Add to `obfuscation_detection.yar`:
```yara
rule P4RS3LT0NGV3_New_Technique {
    meta:
        description = "Detects new obfuscation technique"
        technique = "new_technique"
        
    strings:
        $pattern = /your_pattern_here/
        
    condition:
        $pattern
}
```

### Modifying Detection Sensitivity

Adjust the rule conditions to be more or less sensitive:
- Increase minimum pattern lengths for fewer false positives
- Decrease thresholds for more sensitive detection
- Add more specific patterns for better accuracy

## Analysis and Reporting

The test harness generates:

1. **Console Output**: Real-time test results
2. **Markdown Report**: Detailed analysis with detection rates
3. **JSON Results**: Machine-readable results for further analysis

### Understanding Results

- **Detection Rate**: Percentage of techniques successfully detected
- **False Positives**: Legitimate text flagged as obfuscated
- **False Negatives**: Obfuscated text that wasn't detected
- **Rule Performance**: Which rules are most/least effective

## Security Considerations

This framework is designed for **defensive security research** only:

- ✅ Analyze obfuscation techniques for detection
- ✅ Develop security monitoring rules
- ✅ Research LLM security vulnerabilities
- ✅ Create detection systems

- ❌ Do not use for malicious obfuscation
- ❌ Do not use to evade security systems
- ❌ Do not use for offensive purposes

## Troubleshooting

### Common Issues

1. **Yara not found**: Install yara system package
2. **Unicode issues**: Ensure files are saved as UTF-8
3. **Import errors**: Install yara-python package
4. **Permission errors**: Check file permissions

### Performance

- The test harness processes samples sequentially
- Large test files may take time to process
- Consider splitting very large sample sets

## Contributing

To improve the detection framework:

1. Add new obfuscation techniques to samples
2. Enhance Yara rules for better detection
3. Improve test harness functionality
4. Document findings and improvements

---

**Note**: This framework is part of defensive security research. Use responsibly and in accordance with applicable laws and ethical guidelines.