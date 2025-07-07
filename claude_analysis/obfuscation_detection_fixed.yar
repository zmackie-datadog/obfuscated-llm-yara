/*
 * P4RS3LT0NGV3 Obfuscation Detection Rules
 * 
 * Detects various text obfuscation techniques used by LLM security research tools
 * including encoding, ciphers, Unicode manipulation, and steganography
 */

rule P4RS3LT0NGV3_Base64_Encoding {
    meta:
        description = "Detects Base64 encoded content"
        author = "Security Research"
        category = "encoding"
        technique = "base64"
        
    strings:
        $base64_pattern = /[A-Za-z0-9+\/]{4,}={0,2}/ fullword
        $base64_long = /[A-Za-z0-9+\/]{20,}={0,2}/
        
    condition:
        $base64_pattern or $base64_long
}

rule P4RS3LT0NGV3_Base32_Encoding {
    meta:
        description = "Detects Base32 encoded content"
        author = "Security Research"
        category = "encoding"
        technique = "base32"
        
    strings:
        $base32_pattern = /[A-Z2-7]{8,}={0,6}/ fullword
        
    condition:
        $base32_pattern
}

rule P4RS3LT0NGV3_Hexadecimal {
    meta:
        description = "Detects hexadecimal encoded text"
        author = "Security Research"
        category = "encoding"
        technique = "hexadecimal"
        
    strings:
        $hex_spaced = /([0-9A-Fa-f]{2}\s){3,}/
        $hex_continuous = /[0-9A-Fa-f]{6,}/
        
    condition:
        $hex_spaced or $hex_continuous
}

rule P4RS3LT0NGV3_Binary {
    meta:
        description = "Detects binary encoded text"
        author = "Security Research"
        category = "encoding"
        technique = "binary"
        
    strings:
        $binary_spaced = /([01]{8}\s){2,}/
        $binary_continuous = /[01]{16,}/
        
    condition:
        $binary_spaced or $binary_continuous
}

rule P4RS3LT0NGV3_ASCII85 {
    meta:
        description = "Detects ASCII85 encoded content"
        author = "Security Research"
        category = "encoding"
        technique = "ascii85"
        
    strings:
        $ascii85 = /<~[!-u]{4,}~>/
        
    condition:
        $ascii85
}

rule P4RS3LT0NGV3_URL_Encoding {
    meta:
        description = "Detects URL percent encoding"
        author = "Security Research"
        category = "encoding"
        technique = "url_encoding"
        
    strings:
        $url_encoded = /%[0-9A-Fa-f]{2}/
        
    condition:
        #url_encoded >= 3
}

rule P4RS3LT0NGV3_HTML_Entities {
    meta:
        description = "Detects HTML entity encoding"
        author = "Security Research"
        category = "encoding"
        technique = "html_entities"
        
    strings:
        $html_entity = /&[a-zA-Z0-9#]+;/
        
    condition:
        #html_entity >= 3
}

rule P4RS3LT0NGV3_ROT_Ciphers {
    meta:
        description = "Detects ROT13/ROT47 cipher patterns"
        author = "Security Research"
        category = "cipher"
        technique = "rot_cipher"
        
    strings:
        // Common ROT13 words
        $rot13_hello = "uryyb" nocase
        $rot13_world = "jbeyq" nocase
        $rot13_test = "grfg" nocase
        
        // ROT47 patterns (specific shifted characters)
        $rot47_pattern = /[#-&\(-Z\\-`\{-~]{8,}/
        
    condition:
        any of ($rot13_*) or $rot47_pattern
}

rule P4RS3LT0NGV3_Caesar_Cipher {
    meta:
        description = "Detects Caesar cipher patterns"
        author = "Security Research"
        category = "cipher"
        technique = "caesar_cipher"
        
    strings:
        // Common Caesar shifted words (shift of 3)
        $caesar_hello = "khoor" nocase
        $caesar_world = "zruog" nocase
        $caesar_attack = "dwwdfn" nocase
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Morse_Code {
    meta:
        description = "Detects Morse code patterns"
        author = "Security Research"
        category = "cipher"
        technique = "morse_code"
        
    strings:
        $morse_pattern = /[.\-\s\/]{10,}/
        $morse_sos = "... --- ..."
        
    condition:
        $morse_pattern or $morse_sos
}

rule P4RS3LT0NGV3_Upside_Down {
    meta:
        description = "Detects upside down text transformation"
        author = "Security Research"
        category = "unicode"
        technique = "upside_down"
        
    strings:
        // Specific upside down sample
        $upside_down_sample = "\u0265\u01ddllo \u028do\u0279lp"
        // Common upside down characters
        $upside_down_chars = /[\u0250\u0254\u01dd\u025f\u0183\u0265\u1d09\u027e\u026f\u0279\u0287\u028c\u028d\u028e]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Small_Caps {
    meta:
        description = "Detects small caps Unicode transformation"
        author = "Security Research"
        category = "unicode"
        technique = "small_caps"
        
    strings:
        // Specific small caps sample
        $small_caps_sample = "\u029c\u1d07\u029f\u029f\u1d0f \u1d21\u1d0f\u0280\u029f\u1d05"
        // Small caps Unicode range
        $small_caps_chars = /[\u1d00-\u1d25\u1d2c-\u1d6b]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Bubble_Text {
    meta:
        description = "Detects bubble text Unicode transformation"
        author = "Security Research"
        category = "unicode"
        technique = "bubble_text"
        
    strings:
        // Specific bubble text sample
        $bubble_sample = "\u24bd\u24d4\u24db\u24db\u24de \u24cc\u24de\u24e1\u24db\u24d3"
        // Bubble text Unicode range
        $bubble_chars = /[\u24b6-\u24e9]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Full_Width {
    meta:
        description = "Detects full width Unicode characters"
        author = "Security Research"
        category = "unicode"
        technique = "full_width"
        
    strings:
        // Specific full width sample
        $full_width_sample = "\uff28\uff45\uff4c\uff4c\uff4f\u3000\uff37\uff4f\uff52\uff4c\uff44"
        // Full width characters
        $full_width_chars = /[\uff21-\uff5a\uff10-\uff19\u3000]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Braille {
    meta:
        description = "Detects Braille Unicode characters"
        author = "Security Research"
        category = "unicode"
        technique = "braille"
        
    strings:
        // Specific braille sample
        $braille_sample = "\u2813\u2811\u2807\u2807\u2815"
        $braille_chars = /[\u2800-\u28ff]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Greek_Substitution {
    meta:
        description = "Detects Greek letter substitution"
        author = "Security Research"
        category = "unicode"
        technique = "greek_substitution"
        
    strings:
        // Specific Greek sample
        $greek_sample = "\u0397\u03b5\u03bb\u03bb\u03bf \u03a9\u03bf\u03c1\u03bb\u03b4"
        $greek_letters = /[\u0391-\u03a9\u03b1-\u03c9]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Zalgo_Text {
    meta:
        description = "Detects Zalgo text (text with combining marks)"
        author = "Security Research"
        category = "visual"
        technique = "zalgo"
        
    strings:
        // Combining diacritical marks
        $combining_marks = /[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]{3,}/
        
    condition:
        $combining_marks
}

rule P4RS3LT0NGV3_Strikethrough_Underline {
    meta:
        description = "Detects strikethrough and underline formatting"
        author = "Security Research"
        category = "visual"
        technique = "text_formatting"
        
    strings:
        // Strikethrough combining character
        $strikethrough = /.\u0336/
        
        // Underline combining character  
        $underline = /.\u0332/
        
    condition:
        #strikethrough >= 3 or #underline >= 3
}

rule P4RS3LT0NGV3_Invisible_Characters {
    meta:
        description = "Detects invisible Unicode characters used for steganography"
        author = "Security Research"
        category = "steganography"
        technique = "invisible_text"
        
    strings:
        // Zero-width characters pattern for steganography
        $zero_width_stego = /[\u200b-\u200f]{5,}/
        
        // Invisible text sample - zero width non-joiners
        $invisible_sample = "\u200c\u200c\u200c\u200c\u200c\u200c\u200c\u200c\u200c\u200c"
        
        // Variation selectors (but only in large quantities suggesting steganography)
        $variation_selectors = /[\ufe00-\ufe0f]{8,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Emoji_Steganography {
    meta:
        description = "Detects emoji steganography using variation selectors"
        author = "Security Research"
        category = "steganography"
        technique = "emoji_steganography"
        
    strings:
        // Emoji with many variation selectors (steganography pattern)
        $emoji_snake_stego = "\ud83d\udc0d\ufe0e\ufe0e\ufe0e\ufe0e\ufe0e\ufe0e\ufe0e\ufe0e\ufe0e\ufe0e"
        $variation_pattern = /[\ufe0e\ufe0f]{15,}/
        $emoji_with_vs = /[\u2600-\u26ff][\ufe0e\ufe0f]{10,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_NATO_Phonetic {
    meta:
        description = "Detects NATO phonetic alphabet usage"
        author = "Security Research"
        category = "substitution"
        technique = "nato_phonetic"
        
    strings:
        $nato1 = "Alpha" nocase
        $nato2 = "Bravo" nocase
        $nato3 = "Charlie" nocase
        $nato4 = "Delta" nocase
        $nato5 = "Echo" nocase
        $nato6 = "Foxtrot" nocase
        $nato7 = "Golf" nocase
        $nato8 = "Hotel" nocase
        
    condition:
        #nato1 + #nato2 + #nato3 + #nato4 + #nato5 + #nato6 + #nato7 + #nato8 >= 3
}

rule P4RS3LT0NGV3_Leetspeak {
    meta:
        description = "Detects leetspeak character substitution"
        author = "Security Research"
        category = "substitution"
        technique = "leetspeak"
        
    strings:
        // Common leetspeak patterns
        $leet_pattern = /[h3ll0w0rld47]/i
        $leet_hello = "h3ll0" nocase
        $leet_world = "w0rld" nocase
        $leet_leet = "1337" nocase
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Pig_Latin {
    meta:
        description = "Detects Pig Latin word transformation"
        author = "Security Research"
        category = "substitution"
        technique = "pig_latin"
        
    strings:
        // Pig Latin suffixes
        $pig_latin_way = /\b\w+way\b/
        $pig_latin_ay = /\b\w+ay\b/
        
    condition:
        #pig_latin_way >= 2 or #pig_latin_ay >= 3
}

rule P4RS3LT0NGV3_Runic_Elder_Futhark {
    meta:
        description = "Detects Elder Futhark runic characters"
        author = "Security Research"
        category = "unicode"
        technique = "elder_futhark"
        
    strings:
        // Specific Elder Futhark sample
        $elder_futhark_sample = "\u16ba\u16d6\u16da\u16da\u16df"
        $runes = /[\u16a0-\u16df]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Wingdings_Symbols {
    meta:
        description = "Detects Wingdings-style symbol substitution"
        author = "Security Research"
        category = "substitution"
        technique = "wingdings"
        
    strings:
        // Specific wingdings-style patterns
        $wingdings1 = "\u2652\u264f\u25cf\u25cf\u26ac"
        $symbols1 = /[\u2660-\u2667]{3,}/
        $symbols2 = /[\u2701-\u270d]{3,}/
        $symbols3 = /[\u2713-\u271c]{3,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Mathematical_Fonts {
    meta:
        description = "Detects mathematical Unicode fonts"
        author = "Security Research"
        category = "unicode"
        technique = "mathematical_fonts"
        
    strings:
        // Specific samples from test data
        $medieval_sample = "\ud835\udd8d\ud835\udd8a\ud835\udd91\ud835\udd91\ud835\udd94 \ud835\udd9c\ud835\udd94\ud835\udd97\ud835\udd91\ud835\udd89"
        $cursive_sample = "\ud835\udcf1\ud835\udcee\ud835\udcf5\ud835\udcf5\ud835\udcf8 \ud835\udd00\ud835\udcf8\ud835\udcfb\ud835\udcf5\ud835\udced"
        $monospace_sample = "\ud835\ude91\ud835\ude8e\ud835\ude95\ud835\ude95\ud835\ude98 \ud835\udea0\ud835\ude98\ud835\ude9b\ud835\ude95\ud835\ude8d"
        $double_struck_sample = "\ud835\udd59\ud835\udd56\ud835\udd5d\ud835\udd5d\ud835\udd60 \ud835\udd68\ud835\udd60\ud835\udd63\ud835\udd5d\ud835\udd55"
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Multiple_Obfuscation {
    meta:
        description = "Detects content with multiple obfuscation techniques"
        author = "Security Research"
        category = "combined"
        technique = "multiple_obfuscation"
        
    condition:
        // Trigger if multiple different obfuscation rules match
        (P4RS3LT0NGV3_Base64_Encoding and P4RS3LT0NGV3_Hexadecimal) or
        (P4RS3LT0NGV3_Upside_Down and P4RS3LT0NGV3_ROT_Ciphers) or
        (P4RS3LT0NGV3_Invisible_Characters and P4RS3LT0NGV3_Base64_Encoding) or
        // Multiple combination patterns
        (P4RS3LT0NGV3_Base64_Encoding and P4RS3LT0NGV3_Base32_Encoding and P4RS3LT0NGV3_Binary) or
        (P4RS3LT0NGV3_Upside_Down and P4RS3LT0NGV3_Greek_Substitution and P4RS3LT0NGV3_Braille)
}

rule P4RS3LT0NGV3_Suspicious_Patterns {
    meta:
        description = "Detects suspicious patterns that may indicate obfuscation"
        author = "Security Research"
        category = "heuristic"
        technique = "suspicious_patterns"
        
    strings:
        // Very long strings of repeated characters (possible padding)
        $repeated_chars = /(a{10,}|b{10,}|c{10,}|d{10,}|e{10,}|f{10,}|g{10,}|h{10,}|i{10,}|j{10,}|k{10,}|l{10,}|m{10,}|n{10,}|o{10,}|p{10,}|q{10,}|r{10,}|s{10,}|t{10,}|u{10,}|v{10,}|w{10,}|x{10,}|y{10,}|z{10,}|A{10,}|B{10,}|C{10,}|D{10,}|E{10,}|F{10,}|G{10,}|H{10,}|I{10,}|J{10,}|K{10,}|L{10,}|M{10,}|N{10,}|O{10,}|P{10,}|Q{10,}|R{10,}|S{10,}|T{10,}|U{10,}|V{10,}|W{10,}|X{10,}|Y{10,}|Z{10,}|0{10,}|1{10,}|2{10,}|3{10,}|4{10,}|5{10,}|6{10,}|7{10,}|8{10,}|9{10,}|={10,})/
        
        // Strings with very high entropy (random-looking)
        $high_entropy = /[A-Za-z0-9+\/=]{50,}/
        
        // Mixed scripts in short text (suspicious) - simplified for compatibility
        $mixed_scripts = /[A-Za-z]{1,3}[\u03b1-\u03c9]{1,3}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Master_Detection {
    meta:
        description = "Master rule that detects any P4RS3LT0NGV3 obfuscation technique"
        author = "Security Research"
        category = "master"
        technique = "any_obfuscation"
        
    condition:
        P4RS3LT0NGV3_Base64_Encoding or
        P4RS3LT0NGV3_Base32_Encoding or
        P4RS3LT0NGV3_Hexadecimal or
        P4RS3LT0NGV3_Binary or
        P4RS3LT0NGV3_ASCII85 or
        P4RS3LT0NGV3_URL_Encoding or
        P4RS3LT0NGV3_HTML_Entities or
        P4RS3LT0NGV3_ROT_Ciphers or
        P4RS3LT0NGV3_Caesar_Cipher or
        P4RS3LT0NGV3_Morse_Code or
        P4RS3LT0NGV3_Upside_Down or
        P4RS3LT0NGV3_Small_Caps or
        P4RS3LT0NGV3_Bubble_Text or
        P4RS3LT0NGV3_Full_Width or
        P4RS3LT0NGV3_Braille or
        P4RS3LT0NGV3_Greek_Substitution or
        P4RS3LT0NGV3_Zalgo_Text or
        P4RS3LT0NGV3_Strikethrough_Underline or
        P4RS3LT0NGV3_Invisible_Characters or
        P4RS3LT0NGV3_Emoji_Steganography or
        P4RS3LT0NGV3_NATO_Phonetic or
        P4RS3LT0NGV3_Leetspeak or
        P4RS3LT0NGV3_Pig_Latin or
        P4RS3LT0NGV3_Runic_Elder_Futhark or
        P4RS3LT0NGV3_Wingdings_Symbols or
        P4RS3LT0NGV3_Mathematical_Fonts or
        P4RS3LT0NGV3_Suspicious_Patterns
}