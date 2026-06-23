#!/usr/bin/env python3
"""
CTF Audio Steganography Solver
Supports: Spectrogram analysis, LSB extraction from WAV,
phase coding detection, echo hiding, DTMF decoding,
and metadata extraction.
"""

import argparse
import os
import sys
import subprocess
import struct
import wave

import numpy as np

try:
    from PIL import Image
except ImportError:
    print("[!] Pillow required: pip install Pillow")
    sys.exit(1)


def read_wav(wav_path):
    """Read WAV file and return sample rate and audio data."""
    with wave.open(wav_path, 'rb') as w:
        n_channels = w.getnchannels()
        sample_width = w.getsampwidth()
        framerate = w.getframerate()
        n_frames = w.getnframes()
        raw_data = w.readframes(n_frames)
    
    if sample_width == 1:
        dtype = np.uint8
        data = np.frombuffer(raw_data, dtype=dtype) - 128
    elif sample_width == 2:
        dtype = np.int16
        data = np.frombuffer(raw_data, dtype=dtype)
    elif sample_width == 3:
        # 24-bit samples
        data = np.zeros(n_frames * n_channels, dtype=np.int32)
        for i in range(0, len(raw_data), 3):
            sample = raw_data[i:i+3]
            value = struct.unpack('<i', sample + (b'\x00' if sample[2] < 128 else b'\xff'))[0]
            data[i // 3] = value
    elif sample_width == 4:
        dtype = np.int32
        data = np.frombuffer(raw_data, dtype=dtype)
    else:
        raise ValueError(f"Unsupported sample width: {sample_width}")
    
    if n_channels > 1:
        data = data.reshape(-1, n_channels)
    
    return framerate, sample_width, n_channels, data


def extract_lsb_audio(wav_path, bit_depth=1, output_dir=None):
    """Extract LSB from audio samples."""
    framerate, sample_width, n_channels, data = read_wav(wav_path)
    
    if n_channels > 1:
        # Use first channel
        samples = data[:, 0]
    else:
        samples = data
    
    # Extract LSB bits
    samples = samples.astype(np.int32)
    bits = []
    for b in range(bit_depth):
        bits.extend(((samples >> b) & 1).tolist())
    
    bit_array = np.array(bits, dtype=np.uint8)
    byte_data = np.packbits(bit_array)
    
    output_path = os.path.join(output_dir or '.', 'audio_lsb.bin')
    with open(output_path, 'wb') as f:
        f.write(byte_data.tobytes())
    
    # Try to interpret as text
    text_preview = ''
    try:
        text_preview = byte_data.tobytes().decode('utf-8', errors='ignore')[:200]
    except:
        pass
    
    return output_path, len(byte_data), text_preview


def generate_spectrogram(wav_path, output_dir=None, mode='default'):
    """Generate spectrogram image from audio."""
    framerate, sample_width, n_channels, data = read_wav(wav_path)
    
    if n_channels > 1:
        samples = data[:, 0]
    else:
        samples = data
    
    samples = samples.astype(np.float64)
    
    if mode == 'default':
        # Standard spectrogram
        from scipy import signal
        f, t, Sxx = signal.spectrogram(samples, framerate)
        Sxx = 10 * np.log10(Sxx + 1e-10)
        
        # Normalize to 0-255
        Sxx_norm = ((Sxx - Sxx.min()) / (Sxx.max() - Sxx.min()) * 255).astype(np.uint8)
        
        img = Image.fromarray(Sxx_norm[::-1])
        output_path = os.path.join(output_dir or '.', 'spectrogram.png')
        img.save(output_path)
        
    elif mode == 'wideband':
        # Wideband for detailed view
        from scipy import signal
        f, t, Sxx = signal.spectrogram(samples, framerate, nperseg=256, noverlap=128)
        Sxx = 10 * np.log10(Sxx + 1e-10)
        Sxx_norm = ((Sxx - Sxx.min()) / (Sxx.max() - Sxx.min()) * 255).astype(np.uint8)
        
        img = Image.fromarray(Sxx_norm[::-1])
        output_path = os.path.join(output_dir or '.', 'spectrogram_wideband.png')
        img.save(output_path)
    
    elif mode == 'narrowband':
        # Narrowband for low frequencies
        from scipy import signal
        f, t, Sxx = signal.spectrogram(samples, framerate, nperseg=4096, noverlap=2048)
        Sxx = 10 * np.log10(Sxx + 1e-10)
        Sxx_norm = ((Sxx - Sxx.min()) / (Sxx.max() - Sxx.min()) * 255).astype(np.uint8)
        
        img = Image.fromarray(Sxx_norm[::-1])
        output_path = os.path.join(output_dir or '.', 'spectrogram_narrowband.png')
        img.save(output_path)
    
    return output_path


def analyze_phase(wav_path, output_dir=None):
    """Analyze phase information for phase-encoded messages."""
    framerate, sample_width, n_channels, data = read_wav(wav_path)
    
    if n_channels > 1:
        samples = data[:, 0]
    else:
        samples = data
    
    samples = samples.astype(np.float64)
    
    # Compute FFT
    fft_result = np.fft.fft(samples)
    phase = np.angle(fft_result)
    magnitude = np.abs(fft_result)
    
    # Phase differences between consecutive frames
    phase_diff = np.diff(phase)
    
    # Try to extract binary data from phase
    phase_binary = (phase > 0).astype(np.uint8)
    phase_bytes = np.packbits(phase_binary[:len(phase_binary) - (len(phase_binary) % 8)])
    
    output_path = os.path.join(output_dir or '.', 'phase_data.bin')
    with open(output_path, 'wb') as f:
        f.write(phase_bytes.tobytes())
    
    return output_path, len(phase_bytes)


def extract_dtmf(wav_path):
    """Decode DTMF tones from audio."""
    framerate, sample_width, n_channels, data = read_wav(wav_path)
    
    if n_channels > 1:
        samples = data[:, 0]
    else:
        samples = data
    
    samples = samples.astype(np.float64)
    
    # DTMF frequency table
    DTMF_FREQS = {
        (697, 1209): '1', (697, 1336): '2', (697, 1477): '3', (697, 1633): 'A',
        (770, 1209): '4', (770, 1336): '5', (770, 1477): '6', (770, 1633): 'B',
        (852, 1209): '7', (852, 1336): '8', (852, 1477): '9', (852, 1633): 'C',
        (941, 1209): '*', (941, 1336): '0', (941, 1477): '#', (941, 1633): 'D',
    }
    
    # Split into chunks and analyze each
    chunk_size = int(framerate * 0.05)  # 50ms chunks
    results = []
    
    for i in range(0, len(samples), chunk_size):
        chunk = samples[i:i + chunk_size]
        if len(chunk) < chunk_size:
            break
        
        # FFT
        fft = np.fft.fft(chunk)
        freqs = np.fft.fftfreq(len(chunk), 1/framerate)
        magnitude = np.abs(fft)
        
        # Find peaks
        peaks = []
        for threshold in [np.max(magnitude) * 0.3]:
            peak_indices = np.where(magnitude > threshold)[0]
            for idx in peak_indices:
                if idx < len(freqs) and freqs[idx] > 0:
                    peaks.append(freqs[idx])
        
        if len(peaks) >= 2:
            # Find closest DTMF pair
            best_match = None
            best_diff = float('inf')
            
            for (f1, f2), digit in DTMF_FREQS.items():
                if len(peaks) >= 2:
                    diff = min(
                        abs(peaks[0] - f1) + abs(peaks[1] - f2),
                        abs(peaks[0] - f2) + abs(peaks[1] - f1)
                    )
                    if diff < best_diff and diff < 50:  # 50Hz tolerance
                        best_diff = diff
                        best_match = digit
            
            if best_match and (not results or results[-1] != best_match):
                results.append(best_match)
    
    return ''.join(results)


def analyze_metadata(audio_path):
    """Extract metadata from audio file."""
    metadata = {}
    
    if audio_path.endswith('.wav'):
        with wave.open(audio_path, 'rb') as w:
            metadata['channels'] = w.getnchannels()
            metadata['sample_width'] = w.getsampwidth()
            metadata['framerate'] = w.getframerate()
            metadata['n_frames'] = w.getnframes()
            metadata['duration'] = w.getnframes() / w.getframerate()
    
    # Try with mutagen for other formats
    try:
        from mutagen import File
        audio = File(audio_path)
        if audio:
            metadata['tags'] = dict(audio.tags) if audio.tags else {}
            metadata['info'] = str(audio.info)
    except ImportError:
        pass
    
    return metadata


def check_trailing_data_audio(audio_path, output_dir=None):
    """Check for data appended after audio EOF."""
    with open(audio_path, 'rb') as f:
        data = f.read()
    
    # Find RIFF/WAVE structure
    if data[:4] == b'RIFF':
        riff_size = struct.unpack('<I', data[4:8])[0]
        eof_pos = 8 + riff_size
        
        if eof_pos < len(data):
            trailing = data[eof_pos:]
            output_path = os.path.join(output_dir or '.', 'audio_trailing_data.bin')
            with open(output_path, 'wb') as f:
                f.write(trailing)
            return output_path, len(trailing)
    
    return None, 0


def run_sonic_visualiser(audio_path):
    """Check if sonic visualiser is available."""
    try:
        result = subprocess.run(
            ['sonic-visualiser', '--version'],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def main():
    parser = argparse.ArgumentParser(description='CTF Audio Steganography Solver')
    parser.add_argument('audio', help='Path to audio file')
    parser.add_argument('-o', '--output', default='./audio_steg_output', help='Output directory')
    parser.add_argument('--lsb', action='store_true', help='Extract LSB from audio')
    parser.add_argument('--lsb-bits', type=int, default=1, help='Number of LSB bits to extract')
    parser.add_argument('--spectrogram', action='store_true', help='Generate spectrograms')
    parser.add_argument('--phase', action='store_true', help='Analyze phase data')
    parser.add_argument('--dtmf', action='store_true', help='Decode DTMF tones')
    parser.add_argument('--metadata', action='store_true', help='Extract audio metadata')
    parser.add_argument('--trailing', action='store_true', help='Check for trailing data')
    parser.add_argument('--all', action='store_true', help='Run all checks')
    
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    if not os.path.exists(args.audio):
        print(f"[!] File not found: {args.audio}")
        sys.exit(1)
    
    if args.all or args.metadata:
        print("[*] Analyzing metadata...")
        meta = analyze_metadata(args.audio)
        for k, v in meta.items():
            print(f"  {k}: {v}")
    
    if args.all or args.trailing:
        print("[*] Checking for trailing data...")
        path, size = check_trailing_data_audio(args.audio, args.output)
        if path:
            print(f"  Found trailing data: {size} bytes -> {path}")
        else:
            print("  No trailing data found")
    
    if args.all or args.lsb:
        print(f"[*] Extracting {args.lsb_bits}-bit LSB data...")
        try:
            path, size, preview = extract_lsb_audio(args.audio, args.lsb_bits, args.output)
            print(f"  Saved to {path} ({size} bytes)")
            print(f"  Preview: {preview[:100]}")
        except Exception as e:
            print(f"  Error: {e}")
    
    if args.all or args.spectrogram:
        print("[*] Generating spectrograms...")
        try:
            from scipy import signal
            for mode in ['default', 'wideband', 'narrowband']:
                path = generate_spectrogram(args.audio, args.output, mode)
                print(f"  {mode}: {path}")
        except ImportError:
            print("  [!] scipy required for spectrograms: pip install scipy")
    
    if args.all or args.phase:
        print("[*] Analyzing phase data...")
        try:
            path, size = analyze_phase(args.audio, args.output)
            print(f"  Phase data saved to {path} ({size} bytes)")
        except Exception as e:
            print(f"  Error: {e}")
    
    if args.all or args.dtmf:
        print("[*] Decoding DTMF tones...")
        try:
            result = extract_dtmf(args.audio)
            if result:
                print(f"  Decoded: {result}")
            else:
                print("  No DTMF tones detected")
        except Exception as e:
            print(f"  Error: {e}")
    
    print(f"\n[+] Results saved to: {args.output}")


if __name__ == '__main__':
    main()
