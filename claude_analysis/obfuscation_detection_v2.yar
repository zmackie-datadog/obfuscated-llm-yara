/*
 * P4RS3LT0NGV3 Obfuscation Detection Rules - Version 2 (Ultra-Specific)
 * 
 * Highly specific rules that only match clear obfuscation patterns
 * Designed to minimize false positives on normal text
 */

rule P4RS3LT0NGV3_Base64_Encoding {
    meta:
        description = "Detects Base64 encoded content"
        author = "Security Research"
        category = "encoding"
        technique = "base64"
        
    strings:
        // Very long base64 strings to avoid matching normal text
        $base64_very_long = /[A-Za-z0-9+\/]{64,}={0,2}/ 
        // Base64 with specific patterns that suggest encoding
        $base64_multiline = /([A-Za-z0-9+\/]{40,}(\r?\n)?){2,}={0,2}/
        
    condition:
        $base64_very_long or $base64_multiline
}

rule P4RS3LT0NGV3_Base32_Encoding {
    meta:
        description = "Detects Base32 encoded content"
        author = "Security Research"
        category = "encoding"
        technique = "base32"
        
    strings:
        // Long base32 strings only
        $base32_pattern = /[A-Z2-7]{32,}={0,6}/ fullword
        
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
        // Require substantial hex content
        $hex_spaced = /([0-9A-Fa-f]{2}\s){12,}/
        $hex_continuous = /[0-9A-Fa-f]{48,}/
        
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
        // Require substantial binary content
        $binary_spaced = /([01]{8}\s){8,}/
        $binary_continuous = /[01]{64,}/
        
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
        $ascii85 = /<~[!-u]{20,}~>/
        
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
        #url_encoded >= 15  // Much higher threshold
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
        #html_entity >= 15  // Much higher threshold
}

rule P4RS3LT0NGV3_ROT_Ciphers {
    meta:
        description = "Detects ROT13/ROT47 cipher patterns"
        author = "Security Research"
        category = "cipher"
        technique = "rot_cipher"
        
    strings:
        // Only specific known ROT13 transformations
        $rot13_hello = "uryyb" nocase fullword
        $rot13_world = "jbeyq" nocase fullword
        $rot13_secret = "frperg" nocase fullword
        $rot13_message = "zrffntr" nocase fullword
        
        // ROT47 patterns - very long only
        $rot47_pattern = /[#-&\(-Z\\-`\{-~]{30,}/
        
    condition:
        3 of ($rot13_*) or $rot47_pattern
}

rule P4RS3LT0NGV3_Caesar_Cipher {
    meta:
        description = "Detects Caesar cipher patterns"
        author = "Security Research"
        category = "cipher"
        technique = "caesar_cipher"
        
    strings:
        // Multiple specific Caesar words required
        $caesar_hello = "khoor" nocase fullword
        $caesar_world = "zruog" nocase fullword
        $caesar_attack = "dwwdfn" nocase fullword
        $caesar_secret = "vhfuhw" nocase fullword
        
    condition:
        3 of them
}

rule P4RS3LT0NGV3_Morse_Code {
    meta:
        description = "Detects Morse code patterns"
        author = "Security Research"
        category = "cipher"
        technique = "morse_code"
        
    strings:
        // Clear morse patterns with spacing
        $morse_pattern = /([.\-]{2,7}\s+){8,}/
        $morse_sos = "... --- ..." nocase
        $morse_hello = ".... . .-.. .-.. ---" nocase
        $morse_world = ".-- --- .-. .-.. -.." nocase
        
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
        // Only match actual upside down Unicode characters
        $upside_down_hello = "ɥǝllo ʍoɹlp" nocase
        $upside_down_hello2 = "ɥǝllo" nocase
        $upside_down_world = "ʍoɹlp" nocase
        // Specific upside down characters only
        $upside_chars_a = "ɐ"
        $upside_chars_e = "ǝ"
        $upside_chars_h = "ɥ"
        $upside_chars_w = "ʍ"
        
    condition:
        any of ($upside_down_*) or (2 of ($upside_chars_*))
}

rule P4RS3LT0NGV3_Small_Caps {
    meta:
        description = "Detects small caps Unicode transformation"
        author = "Security Research"
        category = "unicode"
        technique = "small_caps"
        
    strings:
        // Only specific small caps samples
        $small_caps_hello = "ʜᴇʟʟᴏ ᴡᴏʀʟᴅ" nocase
        $small_caps_hello2 = "ʜᴇʟʟᴏ" nocase
        // Specific small caps characters
        $small_caps_h = "ʜ"
        $small_caps_e = "ᴇ"
        $small_caps_l = "ʟ"
        $small_caps_o = "ᴏ"
        
    condition:
        any of ($small_caps_*) or (3 of ($small_caps_h, $small_caps_e, $small_caps_l, $small_caps_o))
}

rule P4RS3LT0NGV3_Bubble_Text {
    meta:
        description = "Detects bubble text Unicode transformation"
        author = "Security Research"
        category = "unicode"
        technique = "bubble_text"
        
    strings:
        // Only specific bubble text samples
        $bubble_hello = "Ⓗⓔⓛⓛⓞ Ⓦⓞⓡⓛⓓ" nocase
        $bubble_hello2 = "Ⓗⓔⓛⓛⓞ" nocase
        // Specific bubble characters
        $bubble_h = "Ⓗ"
        $bubble_e = "ⓔ"
        $bubble_l = "ⓛ"
        $bubble_o = "ⓞ"
        
    condition:
        any of ($bubble_*) or (3 of ($bubble_h, $bubble_e, $bubble_l, $bubble_o))
}

rule P4RS3LT0NGV3_Full_Width {
    meta:
        description = "Detects full width Unicode characters"
        author = "Security Research"
        category = "unicode"
        technique = "full_width"
        
    strings:
        // Only specific full width samples
        $full_width_hello = "Ｈｅｌｌｏ　Ｗｏｒｌｄ" nocase
        $full_width_hello2 = "Ｈｅｌｌｏ" nocase
        // Specific full width characters
        $full_width_h = "Ｈ"
        $full_width_e = "ｅ"
        $full_width_l = "ｌ"
        $full_width_o = "ｏ"
        
    condition:
        any of ($full_width_*) or (3 of ($full_width_h, $full_width_e, $full_width_l, $full_width_o))
}

rule P4RS3LT0NGV3_Braille {
    meta:
        description = "Detects Braille Unicode characters"
        author = "Security Research"
        category = "unicode"
        technique = "braille"
        
    strings:
        // Only specific braille samples
        $braille_hello = "⠓⠑⠇⠇⠕" nocase
        $braille_hello2 = "⠓⠑⠇⠇⠕"
        // Require specific braille patterns, not general ranges
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_Greek_Substitution {
    meta:
        description = "Detects Greek letter substitution for obfuscation"
        author = "Security Research"
        category = "unicode"
        technique = "greek_substitution"
        
    strings:
        // Only specific Greek obfuscation samples
        $greek_hello = "Ηελλο Ωορλδ" nocase
        $greek_hello2 = "Ηελλο" nocase
        // Only trigger on obvious obfuscation, not natural Greek
        $greek_eta = "Η"
        $greek_epsilon = "ε"
        $greek_lambda = "λ"
        $greek_omicron = "ο"
        
    condition:
        any of ($greek_hello*) or (
            $greek_eta and $greek_epsilon and $greek_lambda and $greek_omicron
        )
}

rule P4RS3LT0NGV3_Zalgo_Text {
    meta:
        description = "Detects Zalgo text (text with many combining marks)"
        author = "Security Research"
        category = "visual"
        technique = "zalgo"
        
    strings:
        // Require substantial combining marks
        $combining_marks = /[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]{15,}/
        
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
        // Require many invisible characters
        $zero_width_stego = /[\u200b-\u200f]{20,}/
        $invisible_sample = "‌‌‌‌‌‌‌‌‌‌‌‌‌‌‌‌‌‌‌‌"
        $variation_selectors = /[\ufe00-\ufe0f]{25,}/
        
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
        // Very specific emoji steganography patterns
        $emoji_snake_stego = "🐍︎︎︎︎︎︎︎︎︎︎"
        $variation_pattern = /[\ufe0e\ufe0f]{30,}/
        $emoji_with_vs = /[\u2600-\u26ff][\ufe0e\ufe0f]{20,}/
        
    condition:
        any of them
}

rule P4RS3LT0NGV3_NATO_Phonetic {
    meta:
        description = "Detects NATO phonetic alphabet usage for obfuscation"
        author = "Security Research"
        category = "substitution"
        technique = "nato_phonetic"
        
    strings:
        // NATO words - require many to indicate obfuscation
        $nato_alpha = "Alpha" nocase fullword
        $nato_bravo = "Bravo" nocase fullword
        $nato_charlie = "Charlie" nocase fullword
        $nato_delta = "Delta" nocase fullword
        $nato_echo = "Echo" nocase fullword
        $nato_foxtrot = "Foxtrot" nocase fullword
        $nato_golf = "Golf" nocase fullword
        $nato_hotel = "Hotel" nocase fullword
        $nato_india = "India" nocase fullword
        $nato_juliet = "Juliet" nocase fullword
        
    condition:
        // Require many NATO words to suggest obfuscation
        #nato_alpha + #nato_bravo + #nato_charlie + #nato_delta + #nato_echo + 
        #nato_foxtrot + #nato_golf + #nato_hotel + #nato_india + #nato_juliet >= 8
}

rule P4RS3LT0NGV3_Leetspeak {
    meta:
        description = "Detects leetspeak character substitution"
        author = "Security Research"
        category = "substitution"
        technique = "leetspeak"
        
    strings:
        // Only specific, clear leetspeak words
        $leet_hello = "h3ll0" nocase fullword
        $leet_world = "w0rld" nocase fullword
        $leet_leet = "1337" nocase fullword
        $leet_hacker = "h4ck3r" nocase fullword
        $leet_elite = "31173" nocase fullword
        $leet_password = "p4ssw0rd" nocase fullword
        
    condition:
        3 of them
}

rule P4RS3LT0NGV3_Pig_Latin {
    meta:
        description = "Detects Pig Latin word transformation"
        author = "Security Research"
        category = "substitution"
        technique = "pig_latin"
        
    strings:
        // Specific pig latin transformations
        $pig_hello = "ellohay" nocase fullword
        $pig_world = "orldway" nocase fullword
        $pig_secret = "ecretsay" nocase fullword
        $pig_message = "essagemay" nocase fullword
        
    condition:
        3 of them
}

rule P4RS3LT0NGV3_Runic_Elder_Futhark {
    meta:
        description = "Detects Elder Futhark runic characters"
        author = "Security Research"
        category = "unicode"
        technique = "elder_futhark"
        
    strings:
        // Specific runic samples only
        $elder_futhark_hello = "ᚺᛖᛚᛚᛟ" nocase
        $elder_futhark_hello2 = "ᚺᛖᛚᛚᛟ"
        // Require specific runic patterns, not general ranges
        
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
        // Only specific wingdings patterns
        $wingdings_hello = "♒♏●●⚬" nocase
        $wingdings_hello2 = "♒♏●●⚬"
        // Only specific known wingdings patterns
        
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
        // Only specific mathematical font samples
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
        // Only trigger on clear combinations
        (P4RS3LT0NGV3_Base64_Encoding and (P4RS3LT0NGV3_Hexadecimal or P4RS3LT0NGV3_Binary)) or
        (P4RS3LT0NGV3_Upside_Down and P4RS3LT0NGV3_ROT_Ciphers) or
        (P4RS3LT0NGV3_Invisible_Characters and P4RS3LT0NGV3_Emoji_Steganography) or
        (P4RS3LT0NGV3_Small_Caps and P4RS3LT0NGV3_Bubble_Text and P4RS3LT0NGV3_Full_Width) or
        (P4RS3LT0NGV3_Greek_Substitution and P4RS3LT0NGV3_Braille and P4RS3LT0NGV3_Runic_Elder_Futhark)
}

rule P4RS3LT0NGV3_Suspicious_Patterns {
    meta:
        description = "Detects suspicious patterns that may indicate obfuscation"
        author = "Security Research"
        category = "heuristic"
        technique = "suspicious_patterns"
        
    strings:
        // Very restrictive patterns only
        $repeated_equals = /={30,}/
        $very_high_entropy = /[A-Za-z0-9+\/=]{120,}/
        
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