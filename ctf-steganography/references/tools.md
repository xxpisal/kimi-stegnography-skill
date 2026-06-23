# CTF Steganography Tools Reference

Installation and usage guide for common steganography tools.

## Essential Tools

### binwalk
**Purpose**: Firmware/binary analysis, embedded file extraction
**Install**: `sudo apt install binwalk` or `pip install binwalk`
**Usage**:
```bash
binwalk file.png                    # Scan for signatures
binwalk -e file.png                 # Extract embedded files
binwalk -e -M file.png              # Recursive extraction
binwalk --dd='.*' file.png          # Extract everything
```

### exiftool
**Purpose**: Read/write metadata
**Install**: `sudo apt install libimage-exiftool-perl`
**Usage**:
```bash
exiftool file.jpg                   # Show all metadata
exiftool -all= file.jpg             # Strip metadata
exiftool -Comment='msg' file.jpg    # Write comment
```

### steghide
**Purpose**: Hide data in JPEG/BMP/WAV/AU using graph theory
**Install**: `sudo apt install steghide`
**Usage**:
```bash
steghide info file.jpg              # Check for embedded data
steghide extract -sf file.jpg       # Extract (prompts password)
steghide extract -sf file.jpg -p "" # Extract with empty password
```

### stegseek
**Purpose**: Fast steghide brute-force cracker
**Install**: Download from GitHub releases or `apt install stegseek`
**Usage**:
```bash
stegseek file.jpg wordlist.txt      # Brute force password
stegseek file.jpg /usr/share/wordlists/rockyou.txt
```

### zsteg
**Purpose**: PNG/BMP LSB steganography detection
**Install**: `gem install zsteg`
**Usage**:
```bash
zsteg file.png                      # Run all checks
zsteg -a file.png                   # All (exhaustive)
zsteg -l 3 file.png                 # Check first 3 bit planes
zsteg -b 1,2,3 -o 100 file.png    # Specific bits, offset 100
```

### stegsolve (Java GUI)
**Purpose**: Essential visual image steg analysis tool
**Install**: Download JAR from GitHub
**Usage**:
```bash
java -jar stegsolve.jar             # Launch GUI
# Features: Color planes, bit planes, data extract, stereogram solver
```

### outguess
**Purpose**: Universal steganographic tool (statistical)
**Install**: `sudo apt install outguess`
**Usage**:
```bash
outguess -r file.jpg output.txt     # Extract hidden data
outguess -l file.jpg                # Get capacity estimate
```

### strings
**Purpose**: Extract printable strings
**Usage**:
```bash
strings file.bin                    # All strings
strings -n 8 file.bin               # Minimum 8 chars
strings -e l file.bin               # Little-endian 16-bit
strings -e b file.bin               # Big-endian 16-bit
strings -e L file.bin               # Little-endian 32-bit
```

### foremost
**Purpose**: File carving based on headers/footers
**Install**: `sudo apt install foremost`
**Usage**:
```bash
foremost -i file.bin -o output/     # Extract all files
foremost -t png,jpg -i file.bin     # Specific types only
```

## Audio Tools

### Sonic Visualiser
**Purpose**: Audio visualization including spectrograms
**Install**: `sudo apt install sonic-visualiser`
**Usage**: Open WAV file → Layer → Add Spectrogram

### sox (Sound eXchange)
**Purpose**: Audio processing and conversion
**Install**: `sudo apt install sox libsox-fmt-all`
**Usage**:
```bash
sox input.mp3 output.wav            # Convert to WAV
sox file.wav -n spectrogram         # Generate spectrogram PNG
sox file.wav -n stat                # Audio statistics
```

### Audacity
**Purpose**: Full audio editor with spectrogram view
**Usage**: Import audio → Track dropdown → Spectrogram view

### dee2 (DEE Extraction Engine)
**Purpose**: Audio phase decoding

## Text Tools

### stegsnow
**Purpose**: Whitespace steganography
**Install**: `sudo apt install stegsnow`
**Usage**:
```bash
stegsnow -C file.txt                # Extract message
stegsnow -p password -C file.txt    # With password
```

### Unicode Steganography tools
Python scripts for zero-width character detection (included in this skill).

## Specialized Tools

### f5-steganography
**Purpose**: F5 algorithm implementation for JPEG
**Install**: `pip install f5-steganography`

### silenteye
**Purpose**: Universal steg tool (GUI/CLI)
**Install**: `sudo apt install silenteye`

### pngcheck
**Purpose**: PNG file validation and chunk info
**Install**: `sudo apt install pngcheck`
**Usage**:
```bash
pngcheck -v file.png                # Verbose chunk info
pngcheck -w file.png                # Extract warning info
```

### polyfile
**Purpose**: Polyglot file detection
**Install**: `pip install polyfile`

## Python Libraries

### Pillow (PIL)
```bash
pip install Pillow
```
Image manipulation for custom LSB extraction.

### numpy
```bash
pip install numpy
```
Array operations for bit manipulation.

### scipy
```bash
pip install scipy
```
Signal processing for audio analysis.

### wave
Built-in Python module for WAV file handling.

### mutagen
```bash
pip install mutagen
```
Audio metadata handling.

## Quick Setup (Debian/Ubuntu)

```bash
# Essential system tools
sudo apt update
sudo apt install -y \
    binwalk exiftool steghide stegseek \
    foremost strings pngcheck outguess \
    sonic-visualiser sox audacity \
    stegsnow silenteye \
    python3-pip

# Python libraries
pip3 install Pillow numpy scipy mutagen

# zsteg (requires Ruby)
gem install zsteg

# Wordlists
sudo apt install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```
