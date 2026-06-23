#!/usr/bin/env python3
"""
CTF Steganography Auto-Solver
Automatically detects file type and runs appropriate steganography checks.
Supports: Images (PNG, JPG, GIF, BMP, TIFF), Audio (WAV, MP3), 
Text files, and generic binary files.
"""

import argparse
import os
import sys
import subprocess
import mimetypes
import zipfile
from pathlib import Path

# Import our specialized solvers
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def detect_file_type(file_path):
    """Detect file type using magic bytes and extensions."""
    with open(file_path, 'rb') as f:
        header = f.read(32)
    
    signatures = {
        b'\x89PNG': 'png',
        b'\xff\xd8\xff': 'jpeg',
        b'GIF87a': 'gif',
        b'GIF89a': 'gif',
        b'BM': 'bmp',
        b'II*': 'tiff',
        b'MM*': 'tiff',
        b'RIFF': 'riff',  # Could be WAV or WebP
        b'ID3': 'mp3',
        b'\xff\xfb': 'mp3',
        b'\xff\xf3': 'mp3',
        b'\xff\xf2': 'mp3',
        b'PK\x03\x04': 'zip',
        b'7z\xbc\xaf\x27\x1c': '7z',
        b'Rar!': 'rar',
        b'%PDF': 'pdf',
        b'\x1f\x8b\x08': 'gzip',
        b'\x42\x5a\x68': 'bzip2',
        b'\xfd\x37\x7a\x58\x5a\x00': 'xz',
        b'\x00\x00\x00\x20ftyp': 'mp4',
        b'\x00\x00\x00\x18ftyp': 'mp4',
        b'\x00\x00\x00\x14ftyp': 'mp4',
        b'OggS': 'ogg',
        b'fLaC': 'flac',
        b'FORM': 'aiff',
        b'\x30\x26\xb2\x75\x8e\x66\xcf\x11': 'asf',
    }
    
    # Check magic bytes
    file_type = None
    for sig, ftype in signatures.items():
        if header.startswith(sig):
            file_type = ftype
            break
    
    # Special case: RIFF could be WAV or WebP
    if file_type == 'riff':
        if b'WAVE' in header[:12]:
            file_type = 'wav'
        elif b'WEBP' in header[:12]:
            file_type = 'webp'
    
    # Fall back to extension
    if not file_type:
        ext = Path(file_path).suffix.lower()
        ext_map = {
            '.png': 'png', '.jpg': 'jpeg', '.jpeg': 'jpeg', '.gif': 'gif',
            '.bmp': 'bmp', '.tiff': 'tiff', '.tif': 'tiff',
            '.wav': 'wav', '.mp3': 'mp3', '.ogg': 'ogg', '.flac': 'flac',
            '.txt': 'text', '.md': 'text', '.csv': 'text',
            '.html': 'text', '.xml': 'text', '.json': 'text',
            '.zip': 'zip', '.rar': 'rar', '.7z': '7z',
        }
        file_type = ext_map.get(ext, 'unknown')
    
    return file_type


def solve_image(file_path, output_dir, password_list=None, wordlist=None, deep=False):
    """Run image steganography checks."""
    print("\n" + "="*60)
    print(f"[*] IMAGE STEGANALYSIS: {file_path}")
    print("="*60)
    
    image_steg = __import__('image_steg')
    
    # 1. Metadata
    print("\n[1/8] Extracting metadata...")
    try:
        meta = image_steg.analyze_metadata(file_path)
        for k, v in meta.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 2. Trailing data
    print("\n[2/8] Checking for trailing data...")
    try:
        trailing = image_steg.check_trailing_data(file_path, output_dir)
        if trailing:
            for name, path, size in trailing:
                print(f"  [+] Trailing data found ({name}): {size} bytes -> {path}")
        else:
            print("  No trailing data")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 3. LSB extraction
    print("\n[3/8] Extracting LSB data...")
    try:
        for planes in [[0], [0, 1]]:
            for channels in ['rgb', 'rgba']:
                results = image_steg.extract_lsb(file_path, planes, channels, output_dir)
                for path, size, preview in results:
                    if preview and any(c.isprintable() and not c.isspace() for c in preview):
                        print(f"  [+] {path} ({size} bytes): {preview[:80]}")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 4. Interleaved LSB
    print("\n[4/8] Trying interleaved LSB...")
    try:
        for n in [1, 2]:
            path, size = image_steg.extract_lsb_interleaved(file_path, n, 'rgb', output_dir)
            print(f"  Extracted {path} ({size} bytes)")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 5. Color planes
    print("\n[5/8] Extracting color planes...")
    try:
        planes = image_steg.extract_color_planes(file_path, output_dir)
        print(f"  Extracted {len(planes)} plane images")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 6. Hidden files scan
    print("\n[6/8] Scanning for hidden files...")
    try:
        files = image_steg.scan_for_hidden_files(file_path, output_dir)
        if files:
            for item in files:
                if len(item) == 4:
                    ftype, pos, path, namelist = item
                    print(f"  [+] Valid {ftype} at offset {pos}: {path}")
                    print(f"      Contents: {namelist}")
                else:
                    ftype, pos, path = item
                    print(f"  [+] {ftype} signature at offset {pos}: {path}")
        else:
            print("  No hidden file signatures found")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 7. Binwalk
    print("\n[7/8] Running binwalk...")
    try:
        stdout, stderr = image_steg.run_binwalk(file_path, output_dir)
        if stdout:
            for line in stdout.split('\n')[:20]:
                if line.strip():
                    print(f"  {line}")
        if stderr and "not installed" not in stderr:
            print(f"  Error: {stderr}")
        elif "not installed" in str(stderr):
            print("  binwalk not installed (apt install binwalk)")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 8. Steghide / Stegseek
    print("\n[8/8] Trying steghide extraction...")
    
    # Try empty password
    try:
        results = image_steg.run_steghide(file_path, [''])
        for pwd, status, msg in results:
            if status == 'success':
                print(f"  [+] Extracted with password '{pwd}'")
                break
            elif "not installed" in str(msg):
                print("  steghide not installed (apt install steghide)")
                break
        else:
            print("  steghide: no luck with empty password")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Try stegseek if wordlist provided
    if wordlist and os.path.exists(wordlist):
        print(f"\n[*] Running stegseek with {wordlist}...")
        try:
            stdout, stderr, code = image_steg.run_stegseek(file_path, wordlist)
            if stdout:
                print(f"  {stdout}")
            if stderr:
                print(f"  {stderr}")
        except Exception as e:
            print(f"  Error: {e}")


def solve_audio(file_path, output_dir, deep=False):
    """Run audio steganography checks."""
    print("\n" + "="*60)
    print(f"[*] AUDIO STEGANALYSIS: {file_path}")
    print("="*60)
    
    audio_steg = __import__('audio_steg')
    
    # 1. Metadata
    print("\n[1/6] Extracting metadata...")
    try:
        meta = audio_steg.analyze_metadata(file_path)
        for k, v in meta.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 2. Trailing data
    print("\n[2/6] Checking for trailing data...")
    try:
        path, size = audio_steg.check_trailing_data_audio(file_path, output_dir)
        if path:
            print(f"  [+] Trailing data: {size} bytes -> {path}")
        else:
            print("  No trailing data")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 3. LSB extraction (WAV only)
    if file_path.endswith('.wav'):
        print("\n[3/6] Extracting LSB data...")
        try:
            for bits in [1, 2, 4]:
                path, size, preview = audio_steg.extract_lsb_audio(file_path, bits, output_dir)
                print(f"  {bits}-bit LSB: {path} ({size} bytes)")
                if preview and any(c.isprintable() for c in preview):
                    print(f"    Preview: {preview[:80]}")
        except Exception as e:
            print(f"  Error: {e}")
        
        # 4. Spectrograms
        print("\n[4/6] Generating spectrograms...")
        try:
            from scipy import signal
            for mode in ['default', 'wideband', 'narrowband']:
                path = audio_steg.generate_spectrogram(file_path, output_dir, mode)
                print(f"  [+] {mode} spectrogram: {path}")
            print("  Check spectrogram images for hidden text/visual data!")
        except ImportError:
            print("  scipy not installed: pip install scipy")
        except Exception as e:
            print(f"  Error: {e}")
        
        # 5. Phase analysis
        print("\n[5/6] Analyzing phase data...")
        try:
            path, size = audio_steg.analyze_phase(file_path, output_dir)
            print(f"  Phase data: {path} ({size} bytes)")
        except Exception as e:
            print(f"  Error: {e}")
        
        # 6. DTMF
        print("\n[6/6] Checking for DTMF tones...")
        try:
            result = audio_steg.extract_dtmf(file_path)
            if result:
                print(f"  [+] DTMF decoded: {result}")
            else:
                print("  No DTMF tones detected")
        except Exception as e:
            print(f"  Error: {e}")
    else:
        print("\n[!] LSB/Spectrogram analysis requires WAV format")
        print("    Consider converting: ffmpeg -i input.mp3 output.wav")


def solve_text(file_path, output_dir, deep=False):
    """Run text steganography checks."""
    print("\n" + "="*60)
    print(f"[*] TEXT STEGANALYSIS: {file_path}")
    print("="*60)
    
    text_steg = __import__('text_steg')
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    
    # 1. Zero-width characters
    print("\n[1/7] Checking zero-width characters...")
    found, positions = text_steg.detect_zero_width(text)
    if found:
        print(f"  [+] Found: {found}")
        msg = text_steg.extract_zero_width_message(text)
        if msg:
            for method, decoded in msg:
                print(f"  [+] Hidden message ({method}): {decoded[:200]}")
    else:
        print("  None found")
    
    # 2. Whitespace steganography
    print("\n[2/7] Checking whitespace steganography...")
    ws = text_steg.detect_whitespace_steganography(text)
    print(f"  Spaces: {ws['regular_spaces']}, Tabs: {ws['tabs']}")
    if ws['crlf'] > 0 or ws['lf_only'] > 0:
        print(f"  CRLF: {ws['crlf']}, LF: {ws['lf_only']}")
    msg = text_steg.extract_whitespace_message(text)
    if msg:
        print(f"  [+] Hidden message in trailing whitespace: {msg[:200]}")
    
    # 3. Variation selectors
    print("\n[3/7] Checking variation selectors...")
    vs = text_steg.detect_variation_selectors(text)
    if vs:
        print(f"  [+] Found {len(vs)} variation selectors")
        msg = text_steg.extract_variation_selector_message(text)
        if msg:
            print(f"  [+] Hidden message: {msg[:200]}")
    else:
        print("  None found")
    
    # 4. Homoglyphs
    print("\n[4/7] Checking for homoglyphs...")
    hg = text_steg.detect_homoglyphs(text)
    if hg:
        print(f"  [+] Found {len(hg)} suspicious characters:")
        for pos, char, (ascii_equiv, name) in hg[:10]:
            print(f"      Position {pos}: {name}")
    else:
        print("  None found")
    
    # 5. Braille patterns
    print("\n[5/7] Checking for Braille patterns...")
    bp = text_steg.detect_braille_patterns(text)
    if bp:
        print(f"  [+] Found {len(bp)} Braille characters")
        msg = text_steg.extract_braille_message(text)
        if msg:
            print(f"  [+] Hidden message: {msg[:200]}")
    else:
        print("  None found")
    
    # 6. Line endings
    print("\n[6/7] Analyzing line endings...")
    msg = text_steg.analyze_line_endings(text)
    if msg:
        print(f"  [+] Hidden message: {msg[:200]}")
    else:
        print("  No hidden message in line endings")
    
    # 7. Unicode normalization
    print("\n[7/7] Analyzing Unicode normalization...")
    norm = text_steg.analyze_unicode_normalization(text)
    if 'combining_message' in norm:
        print(f"  [+] Hidden message in combining chars: {norm['combining_message'][:200]}")
    if norm.get('not_nfc') or norm.get('not_nfd'):
        print(f"  [!] Text changes under normalization - possible steganography")


def solve_binary(file_path, output_dir, deep=False):
    """Run generic binary steganography checks."""
    print("\n" + "="*60)
    print(f"[*] BINARY STEGANALYSIS: {file_path}")
    print("="*60)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    print(f"\n[*] File size: {len(data)} bytes")
    print(f"[*] Entropy: {calculate_entropy(data):.4f}")
    
    # Check for embedded strings
    print("\n[1/3] Extracting strings...")
    try:
        result = subprocess.run(
            ['strings', '-n', '8', file_path],
            capture_output=True, text=True, timeout=30
        )
        strings_output = result.stdout.split('\n')
        interesting = [s for s in strings_output if len(s) > 10]
        if interesting:
            print(f"  Found {len(interesting)} interesting strings:")
            for s in interesting[:20]:
                print(f"    {s[:100]}")
    except FileNotFoundError:
        print("  strings command not found")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Scan for file signatures
    print("\n[2/3] Scanning for embedded file signatures...")
    image_steg = __import__('image_steg')
    files = image_steg.scan_for_hidden_files(file_path, output_dir)
    if files:
        for item in files:
            if len(item) == 4:
                ftype, pos, path, namelist = item
                print(f"  [+] Valid {ftype} at offset {pos}: {path}")
            else:
                ftype, pos, path = item
                print(f"  [+] {ftype} at offset {pos}: {path}")
    else:
        print("  No embedded file signatures found")
    
    # Try binwalk
    print("\n[3/3] Running binwalk...")
    try:
        result = subprocess.run(
            ['binwalk', file_path],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout:
            for line in result.stdout.split('\n')[:20]:
                if line.strip():
                    print(f"  {line}")
    except FileNotFoundError:
        print("  binwalk not installed")
    except Exception as e:
        print(f"  Error: {e}")


def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    from collections import Counter
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    import math
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def main():
    parser = argparse.ArgumentParser(
        description='CTF Steganography Auto-Solver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s challenge.png                    # Auto-detect and solve
  %(prog)s -o ./output challenge.wav        # Specify output directory
  %(prog)s --deep challenge.png             # Deep analysis (slower)
  %(prog)s --wordlist dict.txt challenge.jpg # Use custom wordlist
  %(prog)s --type image challenge.jpg       # Force image analysis
        """
    )
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('-o', '--output', default='./steg_solve_output', 
                        help='Output directory (default: ./steg_solve_output)')
    parser.add_argument('--type', choices=['image', 'audio', 'text', 'binary'],
                        help='Force file type (auto-detect if not specified)')
    parser.add_argument('--deep', action='store_true',
                        help='Deep analysis (try more combinations, slower)')
    parser.add_argument('--wordlist', default='/usr/share/wordlists/rockyou.txt',
                        help='Wordlist for password cracking (default: rockyou.txt)')
    parser.add_argument('--passwords', nargs='+', default=[],
                        help='Additional passwords to try')
    parser.add_argument('--solve-type', choices=['lsb', 'metadata', 'trailing', 'all'],
                        default='all', help='Type of analysis to perform')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)
    
    os.makedirs(args.output, exist_ok=True)
    
    print("""
    ╔═══════════════════════════════════════════╗
    ║     CTF Steganography Auto-Solver         ║
    ║                                           ║
    ║  Supports: Image, Audio, Text, Binary     ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Detect file type
    if args.type:
        file_type = args.type
    else:
        file_type = detect_file_type(args.file)
    
    print(f"[*] Detected file type: {file_type}")
    print(f"[*] Analyzing: {args.file}")
    print(f"[*] Output directory: {args.output}")
    
    # Route to appropriate solver
    if file_type in ['png', 'jpeg', 'gif', 'bmp', 'tiff', 'webp']:
        solve_image(args.file, args.output, args.passwords, args.wordlist, args.deep)
    elif file_type in ['wav', 'mp3', 'ogg', 'flac', 'aiff']:
        solve_audio(args.file, args.output, args.deep)
    elif file_type == 'text':
        solve_text(args.file, args.output, args.deep)
    elif file_type in ['zip', 'rar', '7z', 'gzip', 'bzip2', 'xz']:
        print("\n[*] Archive file detected. Extracting first...")
        # Extract and re-analyze
        import tempfile
        extract_dir = os.path.join(args.output, 'extracted')
        os.makedirs(extract_dir, exist_ok=True)
        
        if file_type == 'zip':
            with zipfile.ZipFile(args.file, 'r') as z:
                z.extractall(extract_dir)
        else:
            print(f"[!] Please manually extract the {file_type} file to {extract_dir}")
            sys.exit(0)
        
        # Re-analyze extracted files
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                extracted_path = os.path.join(root, f)
                print(f"\n[*] Analyzing extracted file: {extracted_path}")
                sub_type = detect_file_type(extracted_path)
                if sub_type in ['png', 'jpeg', 'gif', 'bmp', 'tiff', 'webp']:
                    solve_image(extracted_path, args.output, args.deep)
                elif sub_type in ['wav', 'mp3', 'ogg', 'flac']:
                    solve_audio(extracted_path, args.output, args.deep)
                elif sub_type == 'text':
                    solve_text(extracted_path, args.output, args.deep)
    else:
        print(f"\n[*] Unknown/unspecified file type, trying binary analysis...")
        solve_binary(args.file, args.output, args.deep)
    
    print("\n" + "="*60)
    print(f"[+] Analysis complete! Results in: {args.output}")
    print("="*60)


if __name__ == '__main__':
    main()
