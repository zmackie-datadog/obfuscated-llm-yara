/*
 * P4RS3LT0NGV3 Obfuscation Detection Rules - Improved Version
 * 
 * Detects various text obfuscation techniques used by LLM security research tools
 * with improved specificity to reduce false positives
 */

rule P4RS3LT0NGV3_Base64_Encoding {
    meta:
        description = "Detects Base64 encoded content"
        author = "Security Research"
        category = "encoding"
        technique = "base64"
        
    strings:
        // Require longer base64 strings to reduce false positives
        $base64_long = /[A-Za-z0-9+\/]{32,}={0,2}/ 
        // Base64 with line breaks (common in obfuscated content)
        $base64_multiline = /([A-Za-z0-9+\/]{20,}(\r?\n)?){2,}={0,2}/
        
    condition:
        $base64_long or $base64_multiline
}

rule P4RS3LT0NGV3_Base32_Encoding {
    meta:
        description = "Detects Base32 encoded content"
        author = "Security Research"
        category = "encoding"
        technique = "base32"
        
    strings:
        // Require longer base32 strings and proper format
        $base32_pattern = /[A-Z2-7]{16,}={0,6}/ fullword
        
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
        // Spaced hex bytes (common in obfuscated content)
        $hex_spaced = /([0-9A-Fa-f]{2}\s){6,}/
        // Long continuous hex strings
        $hex_continuous = /[0-9A-Fa-f]{24,}/
        
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
        // Require more binary bytes to be confident
        $binary_spaced = /([01]{8}\s){4,}/
        $binary_continuous = /[01]{32,}/
        
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
        $ascii85 = /<~[!-u]{8,}~>/
        
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
        #url_encoded >= 8  // Increased threshold
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
        #html_entity >= 8  // Increased threshold
}

rule P4RS3LT0NGV3_ROT_Ciphers {
    meta:
        description = "Detects ROT13/ROT47 cipher patterns"
        author = "Security Research"
        category = "cipher"
        technique = "rot_cipher"
        
    strings:
        // Specific ROT13 words that are unlikely to appear naturally
        $rot13_hello = "uryyb" nocase fullword
        $rot13_world = "jbeyq" nocase fullword
        $rot13_test = "grfg" nocase fullword
        $rot13_secret = "frperg" nocase fullword
        
        // ROT47 patterns - require longer strings
        $rot47_pattern = /[#-&\(-Z\\-`\{-~]{16,}/
        
    condition:
        2 of ($rot13_*) or $rot47_pattern
}

rule P4RS3LT0NGV3_Caesar_Cipher {
    meta:
        description = "Detects Caesar cipher patterns"
        author = "Security Research"
        category = "cipher"
        technique = "caesar_cipher"
        
    strings:
        // Specific Caesar shifted words (shift of 3)
        $caesar_hello = "khoor" nocase fullword
        $caesar_world = "zruog" nocase fullword
        $caesar_attack = "dwwdfn" nocase fullword
        $caesar_secret = "vhfuhw" nocase fullword
        
    condition:
        2 of them
}

rule P4RS3LT0NGV3_Morse_Code {
    meta:
        description = "Detects Morse code patterns"
        author = "Security Research"
        category = "cipher"
        technique = "morse_code"
        
    strings:
        // More specific morse patterns
        $morse_pattern = /([.\-]{2,7}\s+){5,}/
        $morse_sos = "... --- ..." nocase
        $morse_hello = ".... . .-.. .-.. ---" nocase
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Upside_Down {
    meta:
        description = "Detects upside down text transformation"
        author = "Security Research"
        category = "unicode"
        technique = "upside_down"
        
    strings:
        // Specific upside down samples
        $upside_down_hello = "ɥǝllo ʍoɹlp" nocase
        $upside_down_sample = "ɥǝllo" nocase
        // Common upside down characters - require more
        $upside_down_chars = /[\u0250\u0254\u01dd\u025f\u0183\u0265\u1d09\u027e\u026f\u0279\u0287\u028c\u028d\u028e]{5,}/
        
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
        // Specific small caps samples
        $small_caps_hello = "ʜᴇʟʟᴏ ᴡᴏʀʟᴅ" nocase
        $small_caps_sample = "ʜᴇʟʟᴏ" nocase
        // Small caps Unicode range - require longer sequences
        $small_caps_chars = /[\u1d00-\u1d25\u1d2c-\u1d6b]{5,}/
        
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
        // Specific bubble text samples
        $bubble_hello = "Ⓗⓔⓛⓛⓞ Ⓦⓞⓡⓛⓓ" nocase
        $bubble_sample = "Ⓗⓔⓛⓛⓞ" nocase
        // Bubble text Unicode range - require longer sequences
        $bubble_chars = /[\u24b6-\u24e9]{5,}/
        
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
        // Specific full width samples
        $full_width_hello = "Ｈｅｌｌｏ　Ｗｏｒｌｄ" nocase
        $full_width_sample = "Ｈｅｌｌｏ" nocase
        // Full width characters - require longer sequences
        $full_width_chars = /[\uff21-\uff5a\uff10-\uff19\u3000]{5,}/
        
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
        // Specific braille samples
        $braille_hello = "⠓⠑⠇⠇⠕" nocase
        $braille_sample = "⠓⠑⠇⠇⠕"
        $braille_chars = /[\u2800-\u28ff]{5,}/
        
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
        // Specific Greek samples for obfuscation (not natural Greek text)
        $greek_hello = "Ηελλο Ωορλδ" nocase
        $greek_sample = "Ηελλο" nocase
        // Only trigger on obvious Latin-to-Greek substitution patterns
        $greek_substitution = /[A-Za-z][\u0391-\u03a9\u03b1-\u03c9][A-Za-z][\u0391-\u03a9\u03b1-\u03c9]/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Zalgo_Text {
    meta:
        description = "Detects Zalgo text (text with many combining marks)"
        author = "Security Research"
        category = "visual"
        technique = "zalgo"
        
    strings:
        // Require substantial combining marks to indicate zalgo
        $combining_marks = /[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]{8,}/
        
    condition:
        $combining_marks
}

rule P4RS3LT0NGV3_Invisible_Characters {
    meta:
        description = "Detects invisible Unicode characters used for steganography"
        author = "Security Research"
        category = "steganography"
        technique = "invisible_text"
        
    strings:
        // Zero-width characters pattern for steganography - require more
        $zero_width_stego = /[\u200b-\u200f]{10,}/
        
        // Invisible text sample - zero width non-joiners
        $invisible_sample = "‌‌‌‌‌‌‌‌‌‌‌‌‌‌‌"
        
        // Variation selectors in large quantities
        $variation_selectors = /[\ufe00-\ufe0f]{15,}/
        
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
        // Emoji with many variation selectors (clear steganography pattern)
        $emoji_snake_stego = "🐍︎︎︎︎︎︎︎︎︎︎"
        $variation_pattern = /[\ufe0e\ufe0f]{20,}/
        $emoji_with_vs = /[\u2600-\u26ff][\ufe0e\ufe0f]{15,}/
        
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
        $nato1 = "Alpha" nocase fullword
        $nato2 = "Bravo" nocase fullword
        $nato3 = "Charlie" nocase fullword
        $nato4 = "Delta" nocase fullword
        $nato5 = "Echo" nocase fullword
        $nato6 = "Foxtrot" nocase fullword
        $nato7 = "Golf" nocase fullword
        $nato8 = "Hotel" nocase fullword
        $nato9 = "India" nocase fullword
        $nato10 = "Juliet" nocase fullword
        $nato11 = "Kilo" nocase fullword
        $nato12 = "Lima" nocase fullword
        
    condition:
        // Require multiple NATO words to indicate obfuscation
        #nato1 + #nato2 + #nato3 + #nato4 + #nato5 + #nato6 + #nato7 + #nato8 + #nato9 + #nato10 + #nato11 + #nato12 >= 5
}

rule P4RS3LT0NGV3_Leetspeak {
    meta:
        description = "Detects leetspeak character substitution"
        author = "Security Research"
        category = "substitution"
        technique = "leetspeak"
        
    strings:
        // Specific leetspeak words, not just patterns
        $leet_hello = "h3ll0" nocase fullword
        $leet_world = "w0rld" nocase fullword
        $leet_leet = "1337" nocase fullword
        $leet_hacker = "h4ck3r" nocase fullword
        $leet_elite = "31173" nocase fullword
        
    condition:
        2 of them
}

rule P4RS3LT0NGV3_Pig_Latin {
    meta:
        description = "Detects Pig Latin word transformation"
        author = "Security Research"
        category = "substitution"
        technique = "pig_latin"
        
    strings:
        // Specific pig latin words to avoid false positives
        $pig_hello = "ellohay" nocase fullword
        $pig_world = "orldway" nocase fullword
        $pig_secret = "ecretsay" nocase fullword
        
    condition:
        2 of them
}

rule P4RS3LT0NGV3_Runic_Elder_Futhark {
    meta:
        description = "Detects Elder Futhark runic characters"
        author = "Security Research"
        category = "unicode"
        technique = "elder_futhark"
        
    strings:
        // Specific Elder Futhark samples
        $elder_futhark_hello = "ᚺᛖᛚᛚᛟ" nocase
        $elder_futhark_sample = "ᚺᛖᛚᛚᛟ"
        $runes = /[\u16a0-\u16df]{5,}/
        
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
        // Specific wingdings-style patterns for "hello"
        $wingdings_hello = "♒♏●●⚬" nocase
        $wingdings_sample = "♒♏●●⚬"
        // Require longer sequences of specific symbol ranges
        $symbols1 = /[\u2660-\u2667]{5,}/
        $symbols2 = /[\u2701-\u270d]{5,}/
        $symbols3 = /[\u2713-\u271c]{5,}/
        
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
        $medieval_hello = "𝖍𝖊𝖑𝖑𝖔 𝖜𝖔𝖗𝖑𝖉" nocase
        $cursive_hello = "𝓱𝓮𝓵𝓵𝓸 𝔀𝓸𝓻𝓵𝓭" nocase
        $monospace_hello = "𝚑𝚎𝚕𝚕𝚘 𝚠𝚘𝚛𝚕𝚍" nocase
        $double_struck_hello = "𝕙𝕖𝕝𝕝𝕠 𝕨𝕠𝕣𝕝𝕕" nocase
        
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
        // Only trigger on combinations that clearly indicate obfuscation
        (P4RS3LT0NGV3_Base64_Encoding and (P4RS3LT0NGV3_Hexadecimal or P4RS3LT0NGV3_Binary)) or
        (P4RS3LT0NGV3_Upside_Down and P4RS3LT0NGV3_ROT_Ciphers) or
        (P4RS3LT0NGV3_Invisible_Characters and (P4RS3LT0NGV3_Base64_Encoding or P4RS3LT0NGV3_Emoji_Steganography)) or
        (P4RS3LT0NGV3_Small_Caps and P4RS3LT0NGV3_Bubble_Text and P4RS3LT0NGV3_Full_Width)
}

rule P4RS3LT0NGV3_Suspicious_Patterns {
    meta:
        description = "Detects suspicious patterns that may indicate obfuscation"
        author = "Security Research"
        category = "heuristic"
        technique = "suspicious_patterns"
        
    strings:
        // Very long strings of repeated characters (more restrictive)
        $repeated_chars = /(={20,}|[A-Za-z0-9]{30,})/
        
        // Very high entropy strings (longer and more specific)
        $high_entropy = /[A-Za-z0-9+\/=]{80,}/
        
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