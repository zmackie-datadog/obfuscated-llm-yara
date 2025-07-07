# P4RS3LT0NGV3 Obfuscation Detection Test Report
Generated: 2025-07-07 15:20:15

## Summary
- Total Techniques Tested: 33
- Techniques Detected: 22
- Detection Rate: 66.7%

## Detected Files
- **test_combined_techniques.txt**: 7 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Upside_Down`
  - Rule: `P4RS3LT0NGV3_Small_Caps`
  - Rule: `P4RS3LT0NGV3_Bubble_Text`
  - Rule: `P4RS3LT0NGV3_Braille`
  - Rule: `P4RS3LT0NGV3_Emoji_Steganography`
  - Rule: `P4RS3LT0NGV3_Runic_Elder_Futhark`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_base64_outcome.txt**: 3 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Zalgo_Text`
  - Rule: `P4RS3LT0NGV3_Invisible_Characters`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_hex_outcome.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Hexadecimal`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_ciphers_comprehensive.txt**: 10 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Hexadecimal`
  - Rule: `P4RS3LT0NGV3_Binary`
  - Rule: `P4RS3LT0NGV3_ASCII85`
  - Rule: `P4RS3LT0NGV3_URL_Encoding`
  - Rule: `P4RS3LT0NGV3_HTML_Entities`
  - Rule: `P4RS3LT0NGV3_ROT_Ciphers`
  - Rule: `P4RS3LT0NGV3_Morse_Code`
  - Rule: `P4RS3LT0NGV3_Zalgo_Text`
  - Rule: `P4RS3LT0NGV3_Invisible_Characters`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_braille.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Braille`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_unicode_comprehensive.txt**: 7 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Upside_Down`
  - Rule: `P4RS3LT0NGV3_Small_Caps`
  - Rule: `P4RS3LT0NGV3_Bubble_Text`
  - Rule: `P4RS3LT0NGV3_Full_Width`
  - Rule: `P4RS3LT0NGV3_Braille`
  - Rule: `P4RS3LT0NGV3_Multiple_Obfuscation`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **normal_readme.md**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_ROT_Ciphers`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **normal_code_sample.py**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Zalgo_Text`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_obfuscation_code.py**: 4 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Upside_Down`
  - Rule: `P4RS3LT0NGV3_Braille`
  - Rule: `P4RS3LT0NGV3_Zalgo_Text`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_special_techniques.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Runic_Elder_Futhark`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_unicode_obfuscation.txt**: 6 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Upside_Down`
  - Rule: `P4RS3LT0NGV3_Small_Caps`
  - Rule: `P4RS3LT0NGV3_Bubble_Text`
  - Rule: `P4RS3LT0NGV3_Braille`
  - Rule: `P4RS3LT0NGV3_Runic_Elder_Futhark`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_morse_outcome.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Morse_Code`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_p4rs3lt0ngv3_outputs.txt**: 6 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Upside_Down`
  - Rule: `P4RS3LT0NGV3_Small_Caps`
  - Rule: `P4RS3LT0NGV3_Bubble_Text`
  - Rule: `P4RS3LT0NGV3_Braille`
  - Rule: `P4RS3LT0NGV3_Runic_Elder_Futhark`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_steganography.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Emoji_Steganography`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_emoji_steganography.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Emoji_Steganography`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_leetspeak_outcome.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Leetspeak`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_runes.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Runic_Elder_Futhark`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_encoding_patterns.txt**: 10 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Base64_Encoding`
  - Rule: `P4RS3LT0NGV3_Base32_Encoding`
  - Rule: `P4RS3LT0NGV3_Hexadecimal`
  - Rule: `P4RS3LT0NGV3_Binary`
  - Rule: `P4RS3LT0NGV3_ROT_Ciphers`
  - Rule: `P4RS3LT0NGV3_Morse_Code`
  - Rule: `P4RS3LT0NGV3_Zalgo_Text`
  - Rule: `P4RS3LT0NGV3_Invisible_Characters`
  - Rule: `P4RS3LT0NGV3_Multiple_Obfuscation`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_actual_upside_down.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Upside_Down`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_mixed_obfuscation_outcome.txt**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Upside_Down`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **normal_config.json**: 2 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Zalgo_Text`
  - Rule: `P4RS3LT0NGV3_Master_Detection`
- **test_visual_formatting.txt**: 4 rule(s) matched
  - Rule: `P4RS3LT0NGV3_Zalgo_Text`
  - Rule: `P4RS3LT0NGV3_Invisible_Characters`
  - Rule: `P4RS3LT0NGV3_NATO_Phonetic`
  - Rule: `P4RS3LT0NGV3_Master_Detection`

## Clean Files
- **normal_data.csv**: 1004 bytes
- **moar_zalgo.txt**: 789 bytes
- **test_zalgo_comprehensive.txt**: 876 bytes
- **test_no_obfuscation.txt**: 407 bytes
- **test_minimal_obfuscation.txt**: 410 bytes
- **test_negative_comprehensive.txt**: 619 bytes
- **test_edge_cases.txt**: 365 bytes
- **test_negative_simple.txt**: 438 bytes
- **normal_text_sample1.txt**: 971 bytes
- **test_false_positive_check.txt**: 558 bytes
- **test_actual_zalgo.txt**: 263 bytes

## Detailed Results
### test_combined_techniques.txt
- File: `../test_files/test_combined_techniques.txt`
- Size: 715 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Upside_Down**
    - String `$upside_down_hello2`: 1 instance(s)
    - String `$upside_chars_e`: 1 instance(s)
    - String `$upside_chars_h`: 1 instance(s)
  - **P4RS3LT0NGV3_Small_Caps**
    - String `$small_caps_hello2`: 1 instance(s)
    - String `$small_caps_h`: 1 instance(s)
    - String `$small_caps_e`: 1 instance(s)
    - String `$small_caps_l`: 2 instance(s)
    - String `$small_caps_o`: 1 instance(s)
  - **P4RS3LT0NGV3_Bubble_Text**
    - String `$bubble_e`: 1 instance(s)
    - String `$bubble_l`: 2 instance(s)
    - String `$bubble_o`: 1 instance(s)
  - **P4RS3LT0NGV3_Braille**
    - String `$braille_hello`: 1 instance(s)
    - String `$braille_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Emoji_Steganography**
    - String `$emoji_snake_stego`: 1 instance(s)
  - **P4RS3LT0NGV3_Runic_Elder_Futhark**
    - String `$elder_futhark_hello`: 1 instance(s)
    - String `$elder_futhark_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### normal_data.csv
- File: `../test_files/normal_data.csv`
- Size: 1004 bytes
- Detected: ✗
- No matches

### test_actual_base64_outcome.txt
- File: `../test_files/test_actual_base64_outcome.txt`
- Size: 282 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Zalgo_Text**
    - String `$combining_marks`: 20 instance(s)
  - **P4RS3LT0NGV3_Invisible_Characters**
    - String `$variation_selectors`: 7 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### moar_zalgo.txt
- File: `../test_files/moar_zalgo.txt`
- Size: 789 bytes
- Detected: ✗
- No matches

### test_actual_hex_outcome.txt
- File: `../test_files/test_actual_hex_outcome.txt`
- Size: 266 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Hexadecimal**
    - String `$hex_spaced`: 3 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_ciphers_comprehensive.txt
- File: `../test_files/test_ciphers_comprehensive.txt`
- Size: 1279 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Hexadecimal**
    - String `$hex_spaced`: 21 instance(s)
  - **P4RS3LT0NGV3_Binary**
    - String `$binary_spaced`: 9 instance(s)
  - **P4RS3LT0NGV3_ASCII85**
    - String `$ascii85`: 2 instance(s)
  - **P4RS3LT0NGV3_URL_Encoding**
    - String `$url_encoded`: 18 instance(s)
  - **P4RS3LT0NGV3_HTML_Entities**
    - String `$html_entity`: 15 instance(s)
  - **P4RS3LT0NGV3_ROT_Ciphers**
    - String `$rot47_pattern`: 26 instance(s)
  - **P4RS3LT0NGV3_Morse_Code**
    - String `$morse_sos`: 1 instance(s)
    - String `$morse_hello`: 1 instance(s)
    - String `$morse_world`: 1 instance(s)
  - **P4RS3LT0NGV3_Zalgo_Text**
    - String `$combining_marks`: 81 instance(s)
  - **P4RS3LT0NGV3_Invisible_Characters**
    - String `$zero_width_stego`: 1 instance(s)
    - String `$variation_selectors`: 46 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_zalgo_comprehensive.txt
- File: `../test_files/test_zalgo_comprehensive.txt`
- Size: 876 bytes
- Detected: ✗
- No matches

### test_actual_braille.txt
- File: `../test_files/test_actual_braille.txt`
- Size: 309 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Braille**
    - String `$braille_hello`: 1 instance(s)
    - String `$braille_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_unicode_comprehensive.txt
- File: `../test_files/test_unicode_comprehensive.txt`
- Size: 937 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Upside_Down**
    - String `$upside_chars_a`: 3 instance(s)
    - String `$upside_chars_e`: 5 instance(s)
    - String `$upside_chars_h`: 1 instance(s)
    - String `$upside_chars_w`: 1 instance(s)
  - **P4RS3LT0NGV3_Small_Caps**
    - String `$small_caps_h`: 1 instance(s)
    - String `$small_caps_e`: 2 instance(s)
    - String `$small_caps_l`: 2 instance(s)
    - String `$small_caps_o`: 1 instance(s)
  - **P4RS3LT0NGV3_Bubble_Text**
    - String `$bubble_e`: 6 instance(s)
    - String `$bubble_l`: 4 instance(s)
    - String `$bubble_o`: 2 instance(s)
  - **P4RS3LT0NGV3_Full_Width**
    - String `$full_width_e`: 3 instance(s)
    - String `$full_width_l`: 2 instance(s)
  - **P4RS3LT0NGV3_Braille**
    - String `$braille_hello`: 1 instance(s)
    - String `$braille_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Multiple_Obfuscation**
  - **P4RS3LT0NGV3_Master_Detection**

### test_no_obfuscation.txt
- File: `../test_files/test_no_obfuscation.txt`
- Size: 407 bytes
- Detected: ✗
- No matches

### normal_readme.md
- File: `../test_files/normal_readme.md`
- Size: 2081 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_ROT_Ciphers**
    - String `$rot47_pattern`: 6 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### normal_code_sample.py
- File: `../test_files/normal_code_sample.py`
- Size: 3945 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Zalgo_Text**
    - String `$combining_marks`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_minimal_obfuscation.txt
- File: `../test_files/test_minimal_obfuscation.txt`
- Size: 410 bytes
- Detected: ✗
- No matches

### test_obfuscation_code.py
- File: `../test_files/test_obfuscation_code.py`
- Size: 1577 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Upside_Down**
    - String `$upside_down_hello2`: 1 instance(s)
    - String `$upside_chars_a`: 1 instance(s)
    - String `$upside_chars_e`: 2 instance(s)
    - String `$upside_chars_h`: 1 instance(s)
    - String `$upside_chars_w`: 1 instance(s)
  - **P4RS3LT0NGV3_Braille**
    - String `$braille_hello`: 1 instance(s)
    - String `$braille_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Zalgo_Text**
    - String `$combining_marks`: 13 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_special_techniques.txt
- File: `../test_files/test_special_techniques.txt`
- Size: 1156 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Runic_Elder_Futhark**
    - String `$elder_futhark_hello`: 1 instance(s)
    - String `$elder_futhark_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_unicode_obfuscation.txt
- File: `../test_files/test_unicode_obfuscation.txt`
- Size: 962 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Upside_Down**
    - String `$upside_down_hello`: 1 instance(s)
    - String `$upside_down_hello2`: 1 instance(s)
    - String `$upside_down_world`: 1 instance(s)
    - String `$upside_chars_a`: 1 instance(s)
    - String `$upside_chars_e`: 4 instance(s)
    - String `$upside_chars_h`: 2 instance(s)
    - String `$upside_chars_w`: 2 instance(s)
  - **P4RS3LT0NGV3_Small_Caps**
    - String `$small_caps_hello`: 1 instance(s)
    - String `$small_caps_hello2`: 1 instance(s)
    - String `$small_caps_h`: 2 instance(s)
    - String `$small_caps_e`: 2 instance(s)
    - String `$small_caps_l`: 5 instance(s)
    - String `$small_caps_o`: 3 instance(s)
  - **P4RS3LT0NGV3_Bubble_Text**
    - String `$bubble_e`: 4 instance(s)
    - String `$bubble_l`: 4 instance(s)
    - String `$bubble_o`: 3 instance(s)
  - **P4RS3LT0NGV3_Braille**
    - String `$braille_hello`: 1 instance(s)
    - String `$braille_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Runic_Elder_Futhark**
    - String `$elder_futhark_hello`: 1 instance(s)
    - String `$elder_futhark_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_actual_morse_outcome.txt
- File: `../test_files/test_actual_morse_outcome.txt`
- Size: 270 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Morse_Code**
    - String `$morse_hello`: 1 instance(s)
    - String `$morse_world`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_p4rs3lt0ngv3_outputs.txt
- File: `../test_files/test_p4rs3lt0ngv3_outputs.txt`
- Size: 464 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Upside_Down**
    - String `$upside_chars_a`: 1 instance(s)
    - String `$upside_chars_e`: 5 instance(s)
  - **P4RS3LT0NGV3_Small_Caps**
    - String `$small_caps_e`: 5 instance(s)
    - String `$small_caps_l`: 3 instance(s)
    - String `$small_caps_o`: 2 instance(s)
  - **P4RS3LT0NGV3_Bubble_Text**
    - String `$bubble_hello`: 1 instance(s)
    - String `$bubble_hello2`: 1 instance(s)
    - String `$bubble_h`: 1 instance(s)
    - String `$bubble_e`: 5 instance(s)
    - String `$bubble_l`: 3 instance(s)
    - String `$bubble_o`: 2 instance(s)
  - **P4RS3LT0NGV3_Braille**
    - String `$braille_hello`: 1 instance(s)
    - String `$braille_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Runic_Elder_Futhark**
    - String `$elder_futhark_hello`: 1 instance(s)
    - String `$elder_futhark_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_negative_comprehensive.txt
- File: `../test_files/test_negative_comprehensive.txt`
- Size: 619 bytes
- Detected: ✗
- No matches

### test_steganography.txt
- File: `../test_files/test_steganography.txt`
- Size: 940 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Emoji_Steganography**
    - String `$emoji_snake_stego`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_actual_emoji_steganography.txt
- File: `../test_files/test_actual_emoji_steganography.txt`
- Size: 504 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Emoji_Steganography**
    - String `$emoji_snake_stego`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_edge_cases.txt
- File: `../test_files/test_edge_cases.txt`
- Size: 365 bytes
- Detected: ✗
- No matches

### test_actual_leetspeak_outcome.txt
- File: `../test_files/test_actual_leetspeak_outcome.txt`
- Size: 226 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Leetspeak**
    - String `$leet_hello`: 1 instance(s)
    - String `$leet_world`: 1 instance(s)
    - String `$leet_hacker`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_negative_simple.txt
- File: `../test_files/test_negative_simple.txt`
- Size: 438 bytes
- Detected: ✗
- No matches

### test_actual_runes.txt
- File: `../test_files/test_actual_runes.txt`
- Size: 317 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Runic_Elder_Futhark**
    - String `$elder_futhark_hello`: 1 instance(s)
    - String `$elder_futhark_hello2`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_encoding_patterns.txt
- File: `../test_files/test_encoding_patterns.txt`
- Size: 827 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Base64_Encoding**
    - String `$base64_very_long`: 14 instance(s)
  - **P4RS3LT0NGV3_Base32_Encoding**
    - String `$base32_pattern`: 1 instance(s)
  - **P4RS3LT0NGV3_Hexadecimal**
    - String `$hex_spaced`: 31 instance(s)
  - **P4RS3LT0NGV3_Binary**
    - String `$binary_spaced`: 4 instance(s)
  - **P4RS3LT0NGV3_ROT_Ciphers**
    - String `$rot13_hello`: 1 instance(s)
    - String `$rot47_pattern`: 51 instance(s)
  - **P4RS3LT0NGV3_Morse_Code**
    - String `$morse_hello`: 1 instance(s)
    - String `$morse_world`: 1 instance(s)
  - **P4RS3LT0NGV3_Zalgo_Text**
    - String `$combining_marks`: 71 instance(s)
  - **P4RS3LT0NGV3_Invisible_Characters**
    - String `$variation_selectors`: 56 instance(s)
  - **P4RS3LT0NGV3_Multiple_Obfuscation**
  - **P4RS3LT0NGV3_Master_Detection**

### normal_text_sample1.txt
- File: `../test_files/normal_text_sample1.txt`
- Size: 971 bytes
- Detected: ✗
- No matches

### test_actual_upside_down.txt
- File: `../test_files/test_actual_upside_down.txt`
- Size: 289 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Upside_Down**
    - String `$upside_chars_a`: 5 instance(s)
    - String `$upside_chars_e`: 9 instance(s)
    - String `$upside_chars_h`: 2 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_false_positive_check.txt
- File: `../test_files/test_false_positive_check.txt`
- Size: 558 bytes
- Detected: ✗
- No matches

### test_mixed_obfuscation_outcome.txt
- File: `../test_files/test_mixed_obfuscation_outcome.txt`
- Size: 290 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Upside_Down**
    - String `$upside_chars_a`: 1 instance(s)
    - String `$upside_chars_e`: 6 instance(s)
    - String `$upside_chars_h`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### normal_config.json
- File: `../test_files/normal_config.json`
- Size: 1154 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Zalgo_Text**
    - String `$combining_marks`: 14 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_visual_formatting.txt
- File: `../test_files/test_visual_formatting.txt`
- Size: 840 bytes
- Detected: ✓
- Matches:
  - **P4RS3LT0NGV3_Zalgo_Text**
    - String `$combining_marks`: 64 instance(s)
  - **P4RS3LT0NGV3_Invisible_Characters**
    - String `$variation_selectors`: 35 instance(s)
  - **P4RS3LT0NGV3_NATO_Phonetic**
    - String `$nato_alpha`: 1 instance(s)
    - String `$nato_bravo`: 1 instance(s)
    - String `$nato_charlie`: 1 instance(s)
    - String `$nato_delta`: 1 instance(s)
    - String `$nato_echo`: 1 instance(s)
    - String `$nato_foxtrot`: 1 instance(s)
    - String `$nato_golf`: 1 instance(s)
    - String `$nato_hotel`: 1 instance(s)
    - String `$nato_india`: 1 instance(s)
    - String `$nato_juliet`: 1 instance(s)
  - **P4RS3LT0NGV3_Master_Detection**

### test_actual_zalgo.txt
- File: `../test_files/test_actual_zalgo.txt`
- Size: 263 bytes
- Detected: ✗
- No matches
