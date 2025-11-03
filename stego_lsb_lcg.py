# stego_lsb_lcg.py
from PIL import Image
import numpy as np
import math

def text_to_bits(s):
    return ''.join(f'{ord(c):08b}' for c in s)

def bits_to_text(bstr):
    chars = [bstr[i:i+8] for i in range(0, len(bstr), 8)]
    return ''.join(chr(int(c,2)) for c in chars if len(c)==8)

def lcg_sequence(a, b, m, seed, count):
    x = seed % m
    for _ in range(count):
        x = (a * x + b) % m
        yield x

def embed_bits_into_byte(byte_val, two_bits_str):
    v = (byte_val & ~0b11) | int(two_bits_str, 2)
    return v

def extract_two_bits_from_byte(byte_val):
    return format(byte_val & 0b11, '02b')

def encode_lsb2_lcg(cover_path, message, out_path,
                    a, b, m, seed, length_prefix_bytes=4):
    img = Image.open(cover_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    arr = np.array(img)
    h, w, _ = arr.shape
    num_pixels = h * w
    capacity_bits = num_pixels * 6
    msg_bytes = message.encode('utf-8')
    L = len(msg_bytes)
    if length_prefix_bytes * 8 + len(msg_bytes)*8 > capacity_bits:
        raise ValueError(f"Message too large. capacity bits={capacity_bits}, needed={length_prefix_bytes*8 + len(msg_bytes)*8}")
    length_prefix = L.to_bytes(length_prefix_bytes, 'big')
    payload = length_prefix + msg_bytes
    bits = ''.join(f'{byte:08b}' for byte in payload) 
    if len(bits) % 2 != 0:
        bits += '0'
    two_bit_chunks = [bits[i:i+2] for i in range(0, len(bits), 2)]
    indices_needed = math.ceil(len(two_bit_chunks) / 3)  
    seq = list(lcg_sequence(a,b,m,seed,indices_needed))
    flat = arr.reshape(-1, 3)  
    chunk_idx = 0
    for seq_val in seq:
        idx = seq_val % num_pixels
        rgb = flat[idx]
        new_rgb = []
        for color in rgb:  # R, G, B
            if chunk_idx < len(two_bit_chunks):
                tb = two_bit_chunks[chunk_idx]
                new_color = embed_bits_into_byte(int(color), tb)
                chunk_idx += 1
            else:
                new_color = int(color)
            new_rgb.append(new_color)
        flat[idx] = new_rgb
        if chunk_idx >= len(two_bit_chunks):
            break
    stego_arr = flat.reshape((h, w, 3)).astype(np.uint8)
    stego_img = Image.fromarray(stego_arr, 'RGB')
    stego_img.save(out_path)
    return out_path

def decode_lsb2_lcg(stego_path, a, b, m, seed, length_prefix_bytes=4):

    img = Image.open(stego_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    arr = np.array(img)
    h, w, _ = arr.shape
    num_pixels = h * w
    needed_2bit_chunks_for_length = (length_prefix_bytes * 8) // 2
    indices_needed = math.ceil(needed_2bit_chunks_for_length / 3)
    seq_gen = lcg_sequence(a,b,m,seed,indices_needed)
    flat = arr.reshape(-1,3)
    collected_bits = []
    def collect_n_chunks(n, seq_iter, flat_arr):
        chunks = []
        got = 0
        while got < n:
            try:
                seq_val = next(seq_iter)
            except StopIteration:
                raise ValueError("LCG sequence ended unexpectedly")
            idx = seq_val % flat_arr.shape[0]
            rgb = flat_arr[idx]
            for col in rgb:
                if got >= n: break
                chunks.append(extract_two_bits_from_byte(int(col)))
                got += 1
        return chunks
    seq_iter = lcg_sequence(a,b,m,seed, num_pixels)  
    length_chunks = collect_n_chunks(needed_2bit_chunks_for_length, seq_iter, flat)
    length_bits = ''.join(length_chunks)[:length_prefix_bytes*8]
    msg_len = int(length_bits, 2)
    total_payload_bits = (length_prefix_bytes + msg_len) * 8
    total_chunks = math.ceil(total_payload_bits / 2)
    seq_iter = lcg_sequence(a,b,m,seed, math.ceil(total_chunks/3))
    all_chunks = collect_n_chunks(total_chunks, seq_iter, flat)
    all_bits = ''.join(all_chunks)[:total_payload_bits]
    message_bits = all_bits[length_prefix_bytes*8:]
    if len(message_bits) % 8 != 0:
        message_bits = message_bits + '0' * (8 - (len(message_bits)%8))
    message = bits_to_text(message_bits)
    return message

def psnr(original_path, stego_path):
    o = np.array(Image.open(original_path).convert('RGB')).astype(np.float64)
    s = np.array(Image.open(stego_path).convert('RGB')).astype(np.float64)
    if o.shape != s.shape:
        raise ValueError("Images must be same shape")
    mse = np.mean((o - s) ** 2)
    if mse == 0:
        return float('inf')
    PIXEL_MAX = 255.0
    return 20 * math.log10(PIXEL_MAX / math.sqrt(mse))
