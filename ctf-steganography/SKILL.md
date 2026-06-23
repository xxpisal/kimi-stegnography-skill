---
name: ctf-steganography
description: Comprehensive CTF steganography challenge solver covering image (LSB, metadata, file carving, color planes, steghide), audio (spectrogram, LSB, phase, DTMF), and text (zero-width characters, whitespace, variation selectors, homoglyphs) steganography. Use when tackling CTF challenges involving hidden data in images, audio files, text files, or generic binary files. Automatically detects file types and runs appropriate analysis. Bundles Python scripts for extraction and detection plus technique/tool reference docs.
---

# CTF Steganography Solver

Solve CTF steganography challenges through automated detection and extraction across image, audio, text, and binary file types.

## Quick Start

Run the auto-solver on any challenge file:

```bash
python3 scripts/auto_solver.py challenge.png
python3 scripts/auto_solver.py -o ./output challenge.wav
python3 scripts/auto_solver.py --all --wordlist dict.txt challenge.jpg
```

Run individual solvers for specific file types:

```bash
python3 scripts/image_steg.py --all challenge.png
python3 scripts/audio_steg.py --all challenge.wav
python3 scripts/text_steg.py --all challenge.txt
```

## Workflow

1. **Identify the challenge file** — Note file type, any provided hints, passwords, or context
2. **Run auto-detection** — `auto_solver.py` detects file type and runs all relevant checks
3. **Inspect results** — Check output directory for extracted files, flags, and analysis artifacts
4. **Deep analysis** — For stubborn challenges, run individual solvers with `--deep` or targeted flags
5. **Cross-reference techniques** — Consult `references/techniques.md` for challenge-specific patterns

## File Type Coverage

| File Type | Solver | Key Techniques |
|-----------|--------|----------------|
| PNG, JPG, GIF, BMP, TIFF, WebP | `image_steg.py` | LSB extraction, metadata, trailing data, color planes, file signatures |
| WAV, MP3, OGG, FLAC | `audio_steg.py` | LSB extraction, spectrograms, phase analysis, DTMF, metadata |
| TXT, HTML, JSON, etc. | `text_steg.py` | Zero-width chars, whitespace, variation selectors, homoglyphs, line endings |
| Unknown/Binary | `auto_solver.py` | File signature scan, strings extraction, entropy analysis, binwalk |

## Key Scripts

### auto_solver.py
Main orchestration script. Automatically detects file type and runs the appropriate analysis pipeline.

```bash
python3 scripts/auto_solver.py [options] <file>
  -o, --output DIR       Output directory (default: ./steg_solve_output)
  --type TYPE            Force file type: image|audio|text|binary
  --deep                 Deep analysis (more combinations, slower)
  --wordlist FILE        Wordlist for stegseek (default: rockyou.txt)
  --passwords PWD [..]   Additional passwords to try
```

### image_steg.py
Specialized image steganography solver.

```bash
python3 scripts/image_steg.py [options] <image>
  --lsb                  Extract LSB data
  --lsb-planes 0,1,2     Bit planes to extract
  --lsb-channels rgb     Channels (rgb, rgba, r, g, b)
  --metadata             Extract EXIF/metadata
  --trailing             Check for trailing data after EOF
  --planes               Extract color planes and bit planes
  --scan-files           Scan for hidden file signatures
  --binwalk              Run binwalk
  --steghide             Try steghide extraction
  --stegseek             Run stegseek brute-force
  --diff IMAGE2          Difference analysis between two images
  --all                  Run all checks
```

### audio_steg.py
Specialized audio steganography solver.

```bash
python3 scripts/audio_steg.py [options] <audio>
  --lsb                  Extract LSB from audio
  --lsb-bits N           Number of LSB bits (default: 1)
  --spectrogram          Generate spectrogram images
  --phase                Analyze phase data
  --dtmf                 Decode DTMF tones
  --metadata             Extract audio metadata
  --trailing             Check for trailing data
  --all                  Run all checks
```

### text_steg.py
Specialized text steganography solver.

```bash
python3 scripts/text_steg.py [options] <textfile>
  --zero-width           Detect zero-width characters
  --whitespace           Detect whitespace steganography
  --vs                   Detect variation selectors
  --homoglyphs           Detect homoglyph attacks
  --braille              Detect Braille patterns
  --line-endings         Analyze line ending encoding
  --normalize            Analyze Unicode normalization
  --freq                 Character frequency analysis
  --all                  Run all checks
```

## Common CTF Patterns

Always try these first before running full analysis:

1. `strings -n 8 file | grep -i flag` — Printable strings containing "flag"
2. `file filename` — Verify actual file type vs extension
3. Check for base64 patterns: `[A-Za-z0-9+/=]{20,}`
4. Hex dump first/last 100 bytes: `xxd -l 100 file`
5. Check for `flag{...}`, `ctf{...}`, `FLAG{...}`, `HTB{...}` patterns
6. Try empty password with steghide: `steghide extract -sf file.jpg -p ""`
7. Check if the file is actually a ZIP/Archive with wrong extension

## Required Dependencies

System tools (install as needed):
```bash
apt install binwalk exiftool steghide stegseek foremost strings
```

Python libraries (core requirement):
```bash
pip install Pillow numpy scipy
```

Optional Python libraries:
```bash
pip install scipy mutagen  # For spectrograms and extended audio metadata
```

## References

- **Techniques database**: `references/techniques.md` — Comprehensive catalog of steganography techniques organized by file type. Consult when the auto-solver doesn't find the flag or when you need to understand how a specific technique works.
- **Tools guide**: `references/tools.md` — Installation and usage reference for common CTF steganography tools (binwalk, steghide, stegseek, zsteg, exiftool, etc.). Consult when you need to install or use a specific external tool.

## Technique Selection Guide

When the auto-solver doesn't find the flag, identify the likely technique based on challenge context:

**Image challenges with no password hint** → Try LSB analysis, color planes, trailing data
**Image challenges with password hint** → Try steghide, stegseek, outguess
**Image with visual distortion** → Check specific bit planes, alpha channel
**Audio challenges** → Always check spectrogram first (most common), then LSB
**Text/web challenges** → Check zero-width characters, whitespace, source code comments
**Binary with high entropy** → May be encrypted; try common passwords or look for keys
**Two similar files provided** → Difference analysis or XOR
