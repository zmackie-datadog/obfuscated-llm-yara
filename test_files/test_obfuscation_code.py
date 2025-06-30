#!/usr/bin/env python3
"""
Test file with obfuscation functions that should trigger the YARA rule
"""

def to_upside_down(text):
    """Convert text to upside down characters"""
    upside_down_map = {
        'a': 'ɐ', 'b': 'q', 'c': 'ɔ', 'd': 'p', 'e': 'ǝ'
    }
    return ''.join(upside_down_map.get(c, c) for c in text)

def to_zalgo(text):
    """Convert text to zalgo style"""
    import random
    zalgo_marks = ['\u0300', '\u0301', '\u0302']
    result = ''
    for c in text:
        result += c + random.choice(zalgo_marks)
    return result

def encode_invisible(text):
    """Encode text using invisible Unicode characters"""
    result = ''
    for c in text:
        result += chr(0xE0000 + ord(c) % 0x7F)
    return result

def function_encode_test(data):
    """Test encoding function"""
    return data.encode('utf-8')

def function_decode_test(data):
    """Test decoding function"""
    return data.decode('utf-8')

# JavaScript-style function
js_code = """
function encodeEmoji(emoji, text) {
    return String.fromCodePoint(0xE0000 + text.charCodeAt(0));
}
"""

if __name__ == "__main__":
    test_text = "Hello World"
    print("Original:", test_text)
    print("Upside down:", to_upside_down(test_text))
    print("Zalgo:", to_zalgo(test_text))
    print("Invisible:", encode_invisible(test_text))
    
    # Example outputs that should trigger the rule
    example_upside_down = "ɥǝllo ʍoɹld"
    example_zalgo = "H̸e̊l̥l̯o̊ ̸W̊o̥r̯l̊d̸"
    example_braille = "⠓⠑⠇⠇⠕ ⠺⠕⠗⠇⠙"
    example_base64 = "SGVsbG8gV29ybGQ="
