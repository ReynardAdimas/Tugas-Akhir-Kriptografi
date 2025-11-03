import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import hashlib

def to_bytes(s: str) -> bytes:
    return s.encode('utf-8')


def to_str(b: bytes) -> str:
    return b.decode('utf-8')

def rail_fence_encrypt(plaintext: str, key: int) -> str:
    if key <= 1:
        return plaintext
    rail = [''] * key
    dir_down = False
    row = 0

    for ch in plaintext:
        rail[row] += ch
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        row += 1 if dir_down else -1

    return ''.join(rail)


def rail_fence_decrypt(ciphertext: str, key: int) -> str:
    if key <= 1:
        return ciphertext
    n = len(ciphertext)
    mark = [[False] * n for _ in range(key)]

    dir_down = None
    row, col = 0, 0

    for i in range(n):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        mark[row][col] = True
        col += 1
        row += 1 if dir_down else -1

    idx = 0
    matrix = [[''] * n for _ in range(key)]
    for i in range(key):
        for j in range(n):
            if mark[i][j] and idx < n:
                matrix[i][j] = ciphertext[idx]
                idx += 1

    result = []
    row, col = 0, 0
    for i in range(n):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if matrix[row][col] != '':
            result.append(matrix[row][col])
            col += 1
        row += 1 if dir_down else -1

    return ''.join(result)

PBKDF2_ITERATIONS = 200000
SALT_SIZE = 16
NONCE_SIZE = 12  


def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=hashlib.sha256)


def aes_encrypt(plaintext: str, password: str) -> str:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_SIZE))
    ciphertext, tag = cipher.encrypt_and_digest(to_bytes(plaintext))

    data = salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(data).decode('utf-8')


def aes_decrypt(b64_payload: str, password: str) -> str:
    try:
        data = base64.b64decode(b64_payload)
        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + 16]
        ciphertext = data[SALT_SIZE + NONCE_SIZE + 16:]

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return to_str(plaintext)
    except Exception as e:
        raise ValueError('AES decryption failed. Pastikan password benar dan input tidak korup.')

def super_encrypt(plaintext: str, rail_key: int, aes_password: str) -> str:
    rf = rail_fence_encrypt(plaintext, rail_key)
    aes = aes_encrypt(rf, aes_password)
    return aes


def super_decrypt(ciphertext_b64: str, rail_key: int, aes_password: str) -> str:
    rf_plain = aes_decrypt(ciphertext_b64, aes_password)
    plain = rail_fence_decrypt(rf_plain, rail_key)
    return plain

def main():
    st.set_page_config(page_title='Super Enkripsi (Rail Fence + AES)', layout='centered')

    st.title('Super Enkripsi — Rail Fence + AES (GCM)')
    st.markdown('''
    Aplikasi ini melakukan enkripsi *two-layer*:
    1. **Rail Fence cipher** (zig-zag transposition)
    2. **AES-256 in GCM mode** (dengan derivasi kunci PBKDF2)

    Untuk mendekripsi, masukkan ciphertext (base64) yang dihasilkan oleh tombol **Encrypt**.
    ''')

    mode = st.radio('Mode', ['Encrypt', 'Decrypt'])

    if mode == 'Encrypt':
        plaintext = st.text_area('Plaintext', height=200)
        rail_key = st.number_input('Rail Fence key (jalur / rails)', min_value=2, max_value=50, value=3, step=1)
        aes_password = st.text_input('AES password (kata sandi untuk derivasi kunci)', type='password')

        if st.button('Encrypt (Rail Fence -> AES)'):
            if plaintext.strip() == '':
                st.warning('Teks kosong — masukkan plaintext yang ingin dienkripsi.')
            elif aes_password.strip() == '':
                st.warning('Masukkan password AES (minimal 1 karakter).')
            else:
                try:
                    result = super_encrypt(plaintext, int(rail_key), aes_password)
                    st.success('Berhasil mengenkripsi!')
                    st.code(result, language='text')
                    st.write('Hasil dienkode base64. Simpan ciphertext dan password untuk dekripsi.')
                    st.download_button('Download ciphertext (.txt)', result, file_name='ciphertext.txt')
                except Exception as e:
                    st.error(f'Gagal mengenkripsi: {e}')

    else:  # Decrypt
        ciphertext_b64 = st.text_area('Ciphertext (base64 dari hasil encrypt)', height=200)
        rail_key = st.number_input('Rail Fence key (jalur / rails)', min_value=2, max_value=50, value=3, step=1)
        aes_password = st.text_input('AES password (kata sandi yang sama saat enkripsi)', type='password')

        if st.button('Decrypt (AES -> Rail Fence)'):
            if ciphertext_b64.strip() == '':
                st.warning('Masukkan ciphertext (base64) untuk didekripsi.')
            elif aes_password.strip() == '':
                st.warning('Masukkan password AES.')
            else:
                try:
                    plaintext = super_decrypt(ciphertext_b64.strip(), int(rail_key), aes_password)
                    st.success('Berhasil didekripsi!')
                    st.text_area('Plaintext hasil dekripsi', value=plaintext, height=200)
                except ValueError as ve:
                    st.error(str(ve))
                except Exception as e:
                    st.error('Gagal mendekripsi. Pastikan password, rail key, dan ciphertext benar.')

if __name__ == '__main__':
    main()