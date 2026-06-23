# CTF Steganography Techniques Reference

Comprehensive database of steganography techniques encountered in CTF challenges.

## Table of Contents
- [Image Steganography](#image-steganography)
- [Audio Steganography](#audio-steganography)
- [Text Steganography](#text-steganography)
- [Binary/File Steganography](#binaryfile-steganography)
- [Network Steganography](#network-steganography)

---

## Image Steganography

### 1. LSB (Least Significant Bit)

The most common image steganography technique. Data is hidden in the least significant bits of pixel values.

**Variants:**
- **Sequential LSB**: Data hidden sequentially across pixels
- **Random/Scattered LSB**: Pixels selected by PRNG seeded with passphrase
- **Channel-specific**: Only R, G, B, or A channel used
- **Multi-bit LSB**: Uses 2-4 LSBs for more capacity
- **Interleaved**: Bits distributed across RGB channels in pattern

**Detection:**
- Visual inspection of bit planes (especially plane 0)
- Chi-square attack for known LSB patterns
- RS (Regular-Singular) analysis
- High capacity but often distorts histograms

**Tools:** `zsteg`, `stegsolve`, `stegseek`, `python PIL/numpy`

### 2. Metadata Steganography

Data hidden in image metadata fields.

**Common locations:**
- EXIF comments, artist, copyright fields
- PNG tEXt, zTXt, iTXt chunks
- ICC profile data
- XMP metadata

**Tools:** `exiftool`, `identify -verbose`, `pngcheck`

### 3. File Carving / Append Data

Files concatenated after the image EOF marker.

**Detection:**
- Check file size vs expected image size
- Look for secondary magic bytes after EOF
- `binwalk`, `foremost`, `scalpel`

### 4. Color Plane Analysis

Data hidden in specific color channels or bit planes.

**Variants:**
- **Bit plane slicing**: Each of 8 bits per channel is a binary image
- **Alpha channel**: Hidden in transparency values
- **Color palette**: Indexed color images hide data in palette entries
- **LSB of palette**: Modifying palette colors' LSB

**Tools:** `stegsolve` ( indispensable for this), custom Python

### 5. Transform Domain Techniques

Data hidden in frequency/transform domains.

**Variants:**
- **DCT (Discrete Cosine Transform)**: Used in JPEG steganography (F5, jsteg, outguess)
- **DWT (Discrete Wavelet Transform)**: Wavelet-based hiding
- **FFT**: Frequency domain embedding

**Tools:** `steghide`, `outguess`, `f5-steganography`

### 6. Specific Tools/Formats

| Tool | Detection | Extraction |
|------|-----------|------------|
| steghide | `file` command, steghide info | `steghide extract -sf file.jpg` |
| outguess | Statistical anomalies | `outguess -r file.jpg output.txt` |
| F5 | JPEG DCT histogram analysis | F5 extraction tools |
| SilentEye | LSB in BMP/PNG/WAV | SilentEye GUI or CLI |

---

## Audio Steganography

### 1. LSB in Samples

Similar to image LSB but operates on audio sample values.

**Variants:**
- Sequential LSB in samples
- Distributed across stereo channels
- Multiple LSB bits per sample

**Tools:** `stegoWav`, `hidewav`, Python `wave` module

### 2. Spectrogram Hiding

Data or images encoded in the spectrogram of audio.

**Techniques:**
- Text or QR codes visible in spectrogram view
- Images encoded as frequency patterns
- Spread spectrum techniques

**Tools:** `Sonic Visualiser`, `Audacity` (spectrogram view), `sox`

### 3. Phase Coding

Data hidden in the phase of audio frequencies.

- Modifies phase relationships between frequencies
- Harder to detect than LSB
- Requires original for comparison sometimes

### 4. Echo Hiding

Data encoded as echoes with different delays.

- Short delay = 0, longer delay = 1
- Difficult to detect audibly
- Requires signal processing to extract

### 5. Spread Spectrum

Data spread across frequency spectrum using pseudo-random noise.

- Very robust against compression
- Requires key/seed to extract

---

## Text Steganography

### 1. Zero-Width Characters

Invisible Unicode characters encode binary data.

**Character Map:**
- U+200B (ZWSP) = 0, U+200C (ZWNJ) = 1 (most common)
- U+200D (ZWJ) = separator or 1
- U+FEFF (BOM) = often used as flag

**Detection:** Show all characters with `cat -v` or hex dump
**Tools:** `python text_steg.py`, `Unicode Steganography` tools

### 2. Whitespace Steganography

Spaces and tabs encode binary data, typically at line endings.

**Variants:**
- Trailing spaces = 0, trailing tabs = 1
- Number of spaces encodes value
- Different space characters (en space, em space)

**Tools:** `stegsnow` (Snow whitespace steganography)

### 3. Unicode Variation Selectors

Variation selector characters (U+FE00-U+FE0F, U+E0100-U+E01EF) encode data.

- VS1-VS16: values 0-15
- VS17-VS256: values 16-255
- Often used with emoji or CJK text

### 4. Homoglyph Attacks

Visually similar characters from different scripts.

- Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)
- Greek 'ο' (U+03BF) vs Latin 'o' (U+006F)

**Tools:** Unicode normalization (NFC/NFD), homoglyph detection

### 5. Line-Based Encoding

Data encoded in line properties.

**Variants:**
- Leading spaces count (odd/even = 1/0)
- Line length parity
- Number of words per line
- Sentence length patterns

---

## Binary/File Steganography

### 1. Polyglot Files

Valid as multiple file formats simultaneously.

**Examples:**
- ZIP + PNG (zip comment overlaps PNG data)
- PDF + ZIP
- GIF + JS (GIFAR attack)

**Tools:** `binwalk`, `polyfile`

### 2. Alternate Data Streams (ADS)

Windows NTFS feature hiding data in file streams.

- `dir /r` to list streams
- `more < file:streamname` to read
- `type hidden.txt > file.jpg:hidden.txt` to create

### 3. Slack Space

Data hidden in filesystem slack space.

- Between file end and cluster end
- Requires raw disk access

---

## Network Steganography

### 1. Protocol Field Abuse

Data hidden in unused/reserved protocol fields.

- IP ID field, TCP sequence numbers
- DNS query names (DNS tunneling)
- HTTP headers

### 2. Timing Channels

Data encoded in timing between packets.

- Delay patterns encode bits
- Hard to detect without precise timing

---

## CTF-Specific Patterns

### Common Flag Formats
- `flag{...}`, `ctf{...}`, `FLAG{...}`
- `HTB{...}`, `picoCTF{...}`
- Base64 encoded fragments
- ROT13 or Caesar cipher applied to flag

### Quick Checks (Always Try First)
1. `strings file | grep -i flag`
2. `file` command for actual file type
3. Check for base64 patterns: `[A-Za-z0-9+/=]{20,}`
4. Hex dump first/last 100 bytes
5. Check for known headers at non-zero offsets
6. Check for `flag{...}`, `ctf{...}`, `FLAG{...}`, `HTB{...}` patterns
7. Try empty password with steghide: `steghide extract -sf file.jpg -p ""`
8. Check if the file is actually a ZIP/Archive with wrong extension

### Common CTF Tools Checklist
- [ ] `file` - file type identification
- [ ] `binwalk` - embedded file extraction
- [ ] `foremost` - file carving
- [ ] `strings` - printable string extraction
- [ ] `exiftool` - metadata analysis
- [ ] `xxd/hexdump` - hex viewing
- [ ] `zsteg` - PNG/BMP LSB analysis
- [ ] `steghide` - steghide extraction
- [ ] `stegseek` - fast steghide brute-force
- [ ] `outguess` - outguess extraction
- [ ] `sonic-visualiser` - audio spectrograms
- [ ] `stegsolve` - Java image steg solver
