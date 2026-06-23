#!/usr/bin/env python3
"""
CTF Image Steganography Solver
Supports: LSB extraction, metadata analysis, file carving (binwalk),
color plane analysis, alpha channel extraction, difference analysis,
steghide/brute-force, and more.
"""

import argparse
import os
import sys
import subprocess
import zlib
import struct
import itertools
import zipfile
from io import BytesIO

try:
    from PIL import Image, ExifTags
except ImportError:
    print("[!] Pillow required: pip install Pillow")
    sys.exit(1)

import numpy as np


def extract_lsb(image_path, bit_planes=[0], channels='rgb', output_dir=None):
    """Extract LSB data from specified bit planes and channels."""
    img = Image.open(image_path)
    arr = np.array(img)
    height, width = arr.shape[:2]
    
    channel_map = {'r': 0, 'g': 1, 'b': 2, 'a': 3}
    ch_indices = [channel_map[c] for c in channels.lower() if c in channel_map]
    
    results = []
    for plane in bit_planes:
        for ch in ch_indices:
            if ch >= arr.shape[2]:
                continue
            bits = ((arr[:, :, ch] >> plane) & 1).flatten()
            byte_data = np.packbits(bits)
            result_path = os.path.join(output_dir or '.', f'lsb_p{plane}_ch{ch}.bin')
            with open(result_path, 'wb') as f:
                f.write(byte_data.tobytes())
            # Check if it's text
            text_preview = ''
            try:
                text_preview = byte_data.tobytes().decode('utf-8', errors='ignore')[:200]
            except:
                pass
            results.append((result_path, len(byte_data), text_preview))
    return results


def extract_lsb_interleaved(image_path, n=1, channels='rgb', output_dir=None):
    """Extract LSB data interleaved across channels (common in CTFs)."""
    img = Image.open(image_path)
    arr = np.array(img)
    channel_map = {'r': 0, 'g': 1, 'b': 2, 'a': 3}
    ch_indices = [channel_map[c] for c in channels.lower() if c in channel_map]
    
    bits = []
    for i in range(0, arr.shape[0]):
        for j in range(0, arr.shape[1]):
            for ch in ch_indices:
                if ch >= arr.shape[2]:
                    continue
                pixel_bits = [(arr[i, j, ch] >> b) & 1 for b in range(n)]
                bits.extend(pixel_bits)
    
    byte_data = np.packbits(np.array(bits, dtype=np.uint8))
    result_path = os.path.join(output_dir or '.', f'lsb_interleaved_n{n}.bin')
    with open(result_path, 'wb') as f:
        f.write(byte_data.tobytes())
    return result_path, len(byte_data)


def analyze_metadata(image_path):
    """Extract EXIF and other metadata from image."""
    img = Image.open(image_path)
    metadata = {}
    
    # Basic info
    metadata['format'] = img.format
    metadata['mode'] = img.mode
    metadata['size'] = img.size
    
    # EXIF data
    try:
        exif = img._getexif()
        if exif:
            exif_data = {}
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                exif_data[tag] = str(value)
            metadata['exif'] = exif_data
    except:
        pass
    
    # PNG text chunks
    if img.format == 'PNG':
        png_info = img.info
        metadata['png_info'] = {k: str(v) for k, v in png_info.items()}
    
    # All info
    metadata['info'] = {k: str(v) for k, v in img.info.items()}
    
    return metadata


def check_trailing_data(image_path, output_dir=None):
    """Check for data appended after the image EOF marker."""
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # Find EOF markers
    png_eof = data.find(b'IEND')  # PNG
    jpg_eof = data.find(b'\xff\xd9')  # JPEG
    gif_eof = data.find(b'\x00\x3b')  # GIF
    bmp_eof = 54  # BMP header size
    
    eof_positions = []
    if png_eof != -1:
        eof_positions.append(('PNG IEND', png_eof + 8))
    if jpg_eof != -1:
        eof_positions.append(('JPEG EOI', jpg_eof + 2))
    if gif_eof != -1:
        eof_positions.append(('GIF EOF', gif_eof + 2))
    
    results = []
    for name, eof_pos in eof_positions:
        if eof_pos < len(data):
            trailing = data[eof_pos:]
            if len(trailing) > 0:
                result_path = os.path.join(output_dir or '.', f'trailing_data_{name.lower().replace(" ", "_")}.bin')
                with open(result_path, 'wb') as f:
                    f.write(trailing)
                results.append((name, result_path, len(trailing)))
    
    return results


def extract_color_planes(image_path, output_dir=None):
    """Extract individual color planes and bit planes."""
    img = Image.open(image_path)
    arr = np.array(img)
    
    results = []
    channel_names = ['R', 'G', 'B', 'A'][:arr.shape[2] if len(arr.shape) > 2 else 1]
    
    for i, name in enumerate(channel_names):
        if i >= arr.shape[2]:
            continue
        # Extract full channel
        channel = arr[:, :, i]
        ch_img = Image.fromarray(channel)
        ch_path = os.path.join(output_dir or '.', f'channel_{name}.png')
        ch_img.save(ch_path)
        results.append((f'Channel {name}', ch_path))
        
        # Extract bit planes for this channel
        for bit in range(8):
            bit_plane = ((channel >> bit) & 1) * 255
            bp_img = Image.fromarray(bit_plane.astype(np.uint8))
            bp_path = os.path.join(output_dir or '.', f'channel_{name}_bit{bit}.png')
            bp_img.save(bp_path)
            results.append((f'Channel {name} Bit {bit}', bp_path))
    
    return results


def difference_analysis(image_path1, image_path2, output_dir=None):
    """Compare two images to find differences (useful for challenge pairs)."""
    img1 = Image.open(image_path1).convert('RGB')
    img2 = Image.open(image_path2).convert('RGB')
    
    arr1 = np.array(img1)
    arr2 = np.array(img2)
    
    diff = np.abs(arr1.astype(int) - arr2.astype(int)).astype(np.uint8)
    diff_img = Image.fromarray(diff)
    
    diff_path = os.path.join(output_dir or '.', 'difference.png')
    diff_img.save(diff_path)
    
    # Extract non-zero differences
    mask = np.any(diff > 0, axis=2)
    diff_coords = np.argwhere(mask)
    
    return diff_path, len(diff_coords), diff_coords[:10]


def try_decompress(data):
    """Try various decompression methods on data."""
    results = []
    
    # zlib
    for wbits in [15, -15, 31, 47]:
        try:
            decompressed = zlib.decompress(data, wbits=wbits)
            results.append(('zlib', wbits, decompressed))
        except:
            pass
    
    # gzip
    try:
        import gzip
        decompressed = gzip.decompress(data)
        results.append(('gzip', 0, decompressed))
    except:
        pass
    
    return results


def scan_for_hidden_files(image_path, output_dir=None):
    """Scan for embedded files using magic bytes."""
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # Common file signatures
    signatures = {
        b'\x50\x4b\x03\x04': 'ZIP',
        b'\x52\x61\x72\x21': 'RAR',
        b'\x1f\x8b\x08': 'GZIP',
        b'\x42\x5a\x68': 'BZIP2',
        b'\xfd\x37\x7a\x58\x5a\x00': 'XZ',
        b'\x89PNG': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF8': 'GIF',
        b'BM': 'BMP',
        b'II\x2a\x00': 'TIFF_LE',
        b'MM\x00\x2a': 'TIFF_BE',
        b'%PDF': 'PDF',
        b'\x7b\x5c\x72\x74\x66\x31': 'RTF',
        b'PK\x03\x04': 'ZIP',
    }
    
    found = []
    for sig, ftype in signatures.items():
        offset = 0
        while True:
            pos = data.find(sig, offset)
            if pos == -1:
                break
            
            # Try to extract
            extract_path = os.path.join(output_dir or '.', f'extracted_{ftype}_{pos}.bin')
            with open(extract_path, 'wb') as f:
                f.write(data[pos:])
            found.append((ftype, pos, extract_path))
            
            # For ZIP, try to see if it's a valid archive
            if ftype == 'ZIP':
                try:
                    z = zipfile.ZipFile(extract_path)
                    found.append((f'{ftype}_VALID', pos, extract_path, z.namelist()))
                    z.close()
                except:
                    pass
            
            offset = pos + 1
    
    return found


def run_binwalk(image_path, output_dir=None):
    """Run binwalk if available to find embedded files."""
    try:
        result = subprocess.run(
            ['binwalk', '-e', '-M', '-C', output_dir or '.', image_path],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout, result.stderr
    except FileNotFoundError:
        return None, "binwalk not installed"
    except subprocess.TimeoutExpired:
        return None, "binwalk timed out"


def run_steghide(image_path, password_list=None):
    """Try steghide extraction with password list."""
    results = []
    
    # Try empty password first
    for password in [''] + (password_list or []):
        try:
            cmd = ['steghide', 'extract', '-sf', image_path, '-p', password]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if 'wrote extracted data' in result.stdout.lower() or result.returncode == 0:
                results.append((password or '<empty>', 'success', result.stdout))
            else:
                results.append((password or '<empty>', 'failed', result.stderr))
        except FileNotFoundError:
            return [(None, 'steghide not installed', '')]
        except subprocess.TimeoutExpired:
            results.append((password, 'timeout', ''))
    
    return results


def run_stegseek(image_path, wordlist='/usr/share/wordlists/rockyou.txt'):
    """Run stegseek for fast steghide brute-force."""
    try:
        result = subprocess.run(
            ['stegseek', image_path, wordlist],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return None, "stegseek not installed", -1
    except subprocess.TimeoutExpired:
        return None, "stegseek timed out", -1


def main():
    parser = argparse.ArgumentParser(description='CTF Image Steganography Solver')
    parser.add_argument('image', help='Path to image file')
    parser.add_argument('-o', '--output', default='./steg_output', help='Output directory')
    parser.add_argument('--lsb', action='store_true', help='Extract LSB data')
    parser.add_argument('--lsb-planes', default='0', help='Bit planes to extract (e.g., 0,1,2)')
    parser.add_argument('--lsb-channels', default='rgb', help='Channels to use (rgb, rgba, r, g, b)')
    parser.add_argument('--metadata', action='store_true', help='Extract metadata')
    parser.add_argument('--trailing', action='store_true', help='Check for trailing data')
    parser.add_argument('--planes', action='store_true', help='Extract color planes')
    parser.add_argument('--binwalk', action='store_true', help='Run binwalk')
    parser.add_argument('--steghide', action='store_true', help='Try steghide extraction')
    parser.add_argument('--stegseek', action='store_true', help='Run stegseek brute-force')
    parser.add_argument('--wordlist', default='/usr/share/wordlists/rockyou.txt', help='Wordlist for stegseek')
    parser.add_argument('--scan-files', action='store_true', help='Scan for hidden files by signatures')
    parser.add_argument('--all', action='store_true', help='Run all checks')
    parser.add_argument('--diff', help='Second image for difference analysis')
    
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    if not os.path.exists(args.image):
        print(f"[!] File not found: {args.image}")
        sys.exit(1)
    
    results = []
    
    if args.all or args.metadata:
        print("[*] Analyzing metadata...")
        meta = analyze_metadata(args.image)
        for k, v in meta.items():
            print(f"  {k}: {v}")
    
    if args.all or args.trailing:
        print("[*] Checking for trailing data...")
        trailing = check_trailing_data(args.image, args.output)
        for name, path, size in trailing:
            print(f"  Found trailing data ({name}): {size} bytes -> {path}")
    
    if args.all or args.lsb:
        print("[*] Extracting LSB data...")
        planes = [int(p) for p in args.lsb_planes.split(',')]
        lsb_results = extract_lsb(args.image, planes, args.lsb_channels, args.output)
        for path, size, preview in lsb_results:
            print(f"  {path} ({size} bytes) preview: {preview[:100]}")
    
    if args.all or args.planes:
        print("[*] Extracting color planes...")
        plane_results = extract_color_planes(args.image, args.output)
        for name, path in plane_results:
            print(f"  {name}: {path}")
    
    if args.all or args.scan_files:
        print("[*] Scanning for hidden files...")
        files = scan_for_hidden_files(args.image, args.output)
        for item in files:
            if len(item) == 4:
                ftype, pos, path, namelist = item
                print(f"  Found valid {ftype} at offset {pos}: {path} -> {namelist}")
            else:
                ftype, pos, path = item
                print(f"  Found {ftype} at offset {pos}: {path}")
    
    if args.binwalk:
        print("[*] Running binwalk...")
        stdout, stderr = run_binwalk(args.image, args.output)
        if stdout:
            print(f"  {stdout}")
        if stderr:
            print(f"  Error: {stderr}")
    
    if args.steghide:
        print("[*] Trying steghide extraction...")
        steghide_results = run_steghide(args.image)
        for password, status, msg in steghide_results:
            print(f"  Password '{password}': {status} - {msg}")
    
    if args.stegseek:
        print(f"[*] Running stegseek with wordlist {args.wordlist}...")
        stdout, stderr, code = run_stegseek(args.image, args.wordlist)
        if stdout:
            print(f"  {stdout}")
        if stderr:
            print(f"  {stderr}")
    
    if args.diff:
        print(f"[*] Performing difference analysis with {args.diff}...")
        diff_path, count, samples = difference_analysis(args.image, args.diff, args.output)
        print(f"  Found {count} differing pixels")
        print(f"  Difference image saved to: {diff_path}")
    
    print(f"\n[+] Results saved to: {args.output}")


if __name__ == '__main__':
    main()
