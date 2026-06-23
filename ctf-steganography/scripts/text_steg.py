#!/usr/bin/env python3
"""
CTF Text Steganography Solver
Supports: Whitespace steganography, zero-width characters,
Unicode variation selectors, homoglyph analysis,
line-ending analysis, and more.
"""

import argparse
import os
import sys
import re
import binascii
from collections import Counter


# Zero-width characters used in steganography
ZERO_WIDTH_CHARS = {
    '\u200b': 'ZWSP',      # Zero Width Space
    '\u200c': 'ZWNJ',      # Zero Width Non-Joiner
    '\u200d': 'ZWJ',       # Zero Width Joiner
    '\ufeff': 'BOM',       # Byte Order Mark (also ZWNBSP)
    '\u2060': 'WJ',        # Word Joiner
    '\u180e': 'MVS',       # Mongolian Vowel Separator
    '\u200e': 'LRM',       # Left-to-Right Mark
    '\u200f': 'RLM',       # Right-to-Left Mark
    '\u202a': 'LRE',       # Left-to-Right Embedding
    '\u202b': 'RLE',       # Right-to-Left Embedding
    '\u202c': 'PDF',       # Pop Directional Formatting
    '\u202d': 'LRO',       # Left-to-Right Override
    '\u202e': 'RLO',       # Right-to-Left Override
    '\u2061': 'FA',        # Function Application
    '\u2062': 'IT',        # Invisible Times
    '\u2063': 'IS',        # Invisible Separator
    '\u2064': 'IP',        # Invisible Plus
    '\u2066': 'LRI',       # Left-to-Right Isolate
    '\u2067': 'RLI',       # Right-to-Left Isolate
    '\u2068': 'FSI',       # First Strong Isolate
    '\u2069': 'PDI',       # Pop Directional Isolate
}

# Unicode variation selectors (U+FE00 to U+FE0F and U+E0100 to U+E01EF)
VARIATION_SELECTORS = list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0))

# Braille patterns (U+2800 to U+28FF)
BRAILLE_START = 0x2800


def detect_zero_width(text):
    """Detect and extract zero-width character steganography."""
    found = {}
    positions = []
    
    for char, name in ZERO_WIDTH_CHARS.items():
        if char in text:
            found[name] = text.count(char)
            positions.extend([(m.start(), name) for m in re.finditer(re.escape(char), text)])
    
    positions.sort()
    return found, positions


def extract_zero_width_message(text):
    """Extract hidden message encoded in zero-width characters."""
    # Common encoding: use 2-3 zero-width chars to represent binary
    # e.g., ZWSP=0, ZWNJ=1 or similar patterns
    
    zwsp = '\u200b'   # 0
    zwnj = '\u200c'   # 1
    zwj = '\u200d'    # often used as separator
    
    # Filter only the zero-width chars
    filtered = ''.join(c for c in text if c in (zwsp, zwnj))
    
    if not filtered:
        return None
    
    # Try different interpretations
    results = []
    
    # Interpretation 1: ZWSP=0, ZWNJ=1
    bits = []
    for c in filtered:
        if c == zwsp:
            bits.append(0)
        elif c == zwnj:
            bits.append(1)
    
    if bits:
        # Convert to bytes (8 bits per byte)
        while len(bits) % 8 != 0:
            bits.append(0)
        
        byte_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            byte_data.append(byte)
        
        # Try to decode
        try:
            decoded = byte_data.decode('utf-8', errors='ignore')
            if decoded and any(c.isprintable() for c in decoded):
                results.append(('ZWSP=0/ZWNJ=1', decoded))
        except:
            pass
    
    # Interpretation 2: ZWSP=1, ZWNJ=0
    bits = []
    for c in filtered:
        if c == zwsp:
            bits.append(1)
        elif c == zwnj:
            bits.append(0)
    
    if bits:
        while len(bits) % 8 != 0:
            bits.append(0)
        
        byte_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            byte_data.append(byte)
        
        try:
            decoded = byte_data.decode('utf-8', errors='ignore')
            if decoded and any(c.isprintable() for c in decoded):
                results.append(('ZWSP=1/ZWNJ=0', decoded))
        except:
            pass
    
    return results if results else None


def detect_whitespace_steganography(text):
    """Detect whitespace-based steganography (spaces vs tabs, different spaces)."""
    results = {}
    
    # Count different whitespace characters
    spaces = text.count(' ')       # Regular space U+0020
    tabs = text.count('\t')         # Tab
    nbsps = text.count('\u00a0')   # Non-breaking space
    en_spaces = text.count('\u2002')  # En space
    em_spaces = text.count('\u2003')  # Em space
    
    results['regular_spaces'] = spaces
    results['tabs'] = tabs
    results['non_breaking_spaces'] = nbsps
    results['en_spaces'] = en_spaces
    results['em_spaces'] = em_spaces
    
    # Analyze line endings
    crlf = text.count('\r\n')
    lf_only = len(re.findall(r'(?<!\r)\n', text))
    cr_only = len(re.findall(r'\r(?!\n)', text))
    
    results['crlf'] = crlf
    results['lf_only'] = lf_only
    results['cr_only'] = cr_only
    
    return results


def extract_whitespace_message(text):
    """Extract message hidden in trailing whitespace."""
    lines = text.split('\n')
    
    # Check for trailing spaces/tabs
    trailing = []
    for line in lines:
        stripped = line.rstrip(' \t')
        if len(line) > len(stripped):
            diff = line[len(stripped):]
            trailing.append(diff)
    
    if not trailing:
        return None
    
    # Convert spaces and tabs to binary
    # Common: space=0, tab=1
    bits = []
    for t in trailing:
        for c in t:
            if c == ' ':
                bits.append(0)
            elif c == '\t':
                bits.append(1)
    
    if bits:
        while len(bits) % 8 != 0:
            bits.append(0)
        
        byte_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            byte_data.append(byte)
        
        try:
            return byte_data.decode('utf-8', errors='ignore')
        except:
            pass
    
    return None


def detect_variation_selectors(text):
    """Detect Unicode variation selectors."""
    vs_chars = []
    for i, char in enumerate(text):
        cp = ord(char)
        if (0xFE00 <= cp <= 0xFE0F) or (0xE0100 <= cp <= 0xE01EF):
            vs_chars.append((i, char, cp))
    return vs_chars


def extract_variation_selector_message(text):
    """Extract message encoded in variation selectors."""
    vs_chars = detect_variation_selectors(text)
    
    if not vs_chars:
        return None
    
    # Variation selectors can encode data
    # VS1-VS16 (U+FE00-U+FE0F) = values 0-15
    # VS17-VS256 (U+E0100-U+E01EF) = values 16-255
    
    values = []
    for _, char, cp in vs_chars:
        if 0xFE00 <= cp <= 0xFE0F:
            values.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            values.append(cp - 0xE0100 + 16)
    
    if values:
        try:
            byte_data = bytes(values)
            return byte_data.decode('utf-8', errors='ignore')
        except:
            pass
    
    return None


def analyze_line_endings(text):
    """Analyze line endings for hidden data."""
    lines = text.split('\n')
    
    # Check odd/even space counts
    space_counts = [len(line) - len(line.lstrip(' ')) for line in lines if line.strip()]
    
    # Convert to binary (odd=1, even=0)
    bits = [c % 2 for c in space_counts if c > 0]
    
    if bits:
        while len(bits) % 8 != 0:
            bits.append(0)
        
        byte_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            byte_data.append(byte)
        
        try:
            decoded = byte_data.decode('utf-8', errors='ignore')
            return decoded if any(c.isprintable() for c in decoded) else None
        except:
            pass
    
    return None


def detect_homoglyphs(text):
    """Detect potential homoglyph attacks."""
    # Common Cyrillic/Greek look-alikes
    homoglyphs = {
        'а': ('a', 'CYRILLIC SMALL LETTER A'),
        'е': ('e', 'CYRILLIC SMALL LETTER IE'),
        'о': ('o', 'CYRILLIC SMALL LETTER O'),
        'р': ('p', 'CYRILLIC SMALL LETTER ER'),
        'с': ('c', 'CYRILLIC SMALL LETTER ES'),
        'х': ('x', 'CYRILLIC SMALL LETTER HA'),
        'і': ('i', 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I'),
        'ј': ('j', 'CYRILLIC SMALL LETTER JE'),
    }
    
    found = []
    for i, char in enumerate(text):
        if char in homoglyphs:
            found.append((i, char, homoglyphs[char]))
    
    return found


def detect_braille_patterns(text):
    """Detect Braille pattern characters (U+2800-U+28FF)."""
    braille_chars = []
    for i, char in enumerate(text):
        cp = ord(char)
        if BRAILLE_START <= cp <= BRAILLE_START + 0xFF:
            braille_chars.append((i, char, cp - BRAILLE_START))
    return braille_chars


def extract_braille_message(text):
    """Extract message encoded in Braille patterns."""
    braille_chars = detect_braille_patterns(text)
    
    if not braille_chars:
        return None
    
    # Braille characters encode 8 dots (bits)
    # U+2800 = blank (all dots off)
    # Values 0x01-0xFF represent different dot patterns
    
    values = [v for _, _, v in braille_chars]
    
    try:
        byte_data = bytes(values)
        return byte_data.decode('utf-8', errors='ignore')
    except:
        pass
    
    return None


def analyze_unicode_normalization(text):
    """Analyze text for Unicode normalization differences."""
    import unicodedata
    
    nfd = unicodedata.normalize('NFD', text)
    nfc = unicodedata.normalize('NFC', text)
    nfkd = unicodedata.normalize('NFKD', text)
    nfkc = unicodedata.normalize('NFKC', text)
    
    results = {
        'original_length': len(text),
        'nfc_length': len(nfc),
        'nfd_length': len(nfd),
        'nfkc_length': len(nfkc),
        'nfkd_length': len(nfkd),
    }
    
    if text != nfc:
        results['not_nfc'] = True
    if text != nfd:
        results['not_nfd'] = True
    
    # Find combining characters in NFD
    combining = [c for c in nfd if unicodedata.combining(c) > 0]
    if combining:
        results['combining_chars'] = len(combining)
        # Could encode data in combining characters
        bits = [unicodedata.combining(c) for c in combining]
        if bits:
            try:
                byte_data = bytes(b for b in bits if 0 <= b <= 255)
                decoded = byte_data.decode('utf-8', errors='ignore')
                if decoded and any(c.isprintable() for c in decoded):
                    results['combining_message'] = decoded
            except:
                pass
    
    return results


def analyze_character_frequencies(text):
    """Analyze character frequencies for anomalies."""
    counter = Counter(text)
    total = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * (p.bit_length() - 1)  # Approximate log2
    
    # Check for unusual character distributions
    ascii_chars = sum(1 for c in text if ord(c) < 128)
    non_ascii = total - ascii_chars
    
    return {
        'total_chars': total,
        'unique_chars': len(counter),
        'ascii_ratio': ascii_chars / total if total > 0 else 0,
        'non_ascii': non_ascii,
        'most_common': counter.most_common(10),
    }


def detect_steganography(text):
    """Run all detection methods and return comprehensive results."""
    results = {
        'zero_width': detect_zero_width(text),
        'zero_width_message': extract_zero_width_message(text),
        'whitespace': detect_whitespace_steganography(text),
        'whitespace_message': extract_whitespace_message(text),
        'variation_selectors': detect_variation_selectors(text),
        'vs_message': extract_variation_selector_message(text),
        'homoglyphs': detect_homoglyphs(text),
        'braille': detect_braille_patterns(text),
        'braille_message': extract_braille_message(text),
        'line_endings': analyze_line_endings(text),
        'normalization': analyze_unicode_normalization(text),
        'frequencies': analyze_character_frequencies(text),
    }
    return results


def main():
    parser = argparse.ArgumentParser(description='CTF Text Steganography Solver')
    parser.add_argument('file', help='Path to text file')
    parser.add_argument('-o', '--output', default='./text_steg_output', help='Output directory')
    parser.add_argument('--all', action='store_true', help='Run all checks')
    parser.add_argument('--zero-width', action='store_true', help='Detect zero-width characters')
    parser.add_argument('--whitespace', action='store_true', help='Detect whitespace steganography')
    parser.add_argument('--vs', action='store_true', help='Detect variation selectors')
    parser.add_argument('--homoglyphs', action='store_true', help='Detect homoglyphs')
    parser.add_argument('--braille', action='store_true', help='Detect Braille patterns')
    parser.add_argument('--line-endings', action='store_true', help='Analyze line endings')
    parser.add_argument('--normalize', action='store_true', help='Analyze Unicode normalization')
    parser.add_argument('--freq', action='store_true', help='Analyze character frequencies')
    
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)
    
    with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    
    run_all = args.all or not any([
        args.zero_width, args.whitespace, args.vs,
        args.homoglyphs, args.braille, args.line_endings,
        args.normalize, args.freq
    ])
    
    if run_all or args.zero_width:
        print("[*] Checking for zero-width characters...")
        found, positions = detect_zero_width(text)
        if found:
            print(f"  Found: {found}")
            msg = extract_zero_width_message(text)
            if msg:
                for method, decoded in msg:
                    print(f"  Hidden message ({method}): {decoded[:200]}")
        else:
            print("  None found")
    
    if run_all or args.whitespace:
        print("[*] Checking whitespace steganography...")
        ws = detect_whitespace_steganography(text)
        print(f"  Spaces: {ws['regular_spaces']}, Tabs: {ws['tabs']}")
        print(f"  CRLF: {ws['crlf']}, LF: {ws['lf_only']}, CR: {ws['cr_only']}")
        msg = extract_whitespace_message(text)
        if msg:
            print(f"  Hidden message in trailing whitespace: {msg[:200]}")
    
    if run_all or args.vs:
        print("[*] Checking variation selectors...")
        vs = detect_variation_selectors(text)
        if vs:
            print(f"  Found {len(vs)} variation selectors")
            msg = extract_variation_selector_message(text)
            if msg:
                print(f"  Hidden message: {msg[:200]}")
        else:
            print("  None found")
    
    if run_all or args.homoglyphs:
        print("[*] Checking for homoglyphs...")
        hg = detect_homoglyphs(text)
        if hg:
            print(f"  Found {len(hg)} suspicious characters:")
            for pos, char, (ascii_equiv, name) in hg[:10]:
                print(f"    Position {pos}: {name} (looks like '{ascii_equiv}')")
        else:
            print("  None found")
    
    if run_all or args.braille:
        print("[*] Checking for Braille patterns...")
        bp = detect_braille_patterns(text)
        if bp:
            print(f"  Found {len(bp)} Braille characters")
            msg = extract_braille_message(text)
            if msg:
                print(f"  Hidden message: {msg[:200]}")
        else:
            print("  None found")
    
    if run_all or args.line_endings:
        print("[*] Analyzing line endings...")
        msg = analyze_line_endings(text)
        if msg:
            print(f"  Hidden message: {msg[:200]}")
        else:
            print("  No hidden message in line endings")
    
    if run_all or args.normalize:
        print("[*] Analyzing Unicode normalization...")
        norm = analyze_unicode_normalization(text)
        print(f"  Original length: {norm['original_length']}")
        print(f"  NFC length: {norm['nfc_length']}")
        if 'combining_chars' in norm:
            print(f"  Combining characters: {norm['combining_chars']}")
        if 'combining_message' in norm:
            print(f"  Hidden message: {norm['combining_message'][:200]}")
    
    if run_all or args.freq:
        print("[*] Analyzing character frequencies...")
        freq = analyze_character_frequencies(text)
        print(f"  Total chars: {freq['total_chars']}")
        print(f"  Unique chars: {freq['unique_chars']}")
        print(f"  ASCII ratio: {freq['ascii_ratio']:.2%}")
        print(f"  Top characters: {freq['most_common']}")
    
    print(f"\n[+] Analysis complete")


if __name__ == '__main__':
    main()
