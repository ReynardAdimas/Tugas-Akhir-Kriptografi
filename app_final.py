import streamlit as st
import pymongo
import hashlib
import base64 
import io
from PIL import Image
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import Blowfish
from datetime import datetime

# DB Connect

@st.cache_resource
def init_connection():
    try:
        CONNECTION_STRING = "mongodb://localhost:27017/"
        client = pymongo.MongoClient(CONNECTION_STRING)
        client.admin.command('ping')
        st.success("✅ Berhasil terhubung!")
        return client
    except Exception as e:
        st.error(f"❌ Gagal Terhubung: {e}")
        return None

client = init_connection()
if client:
    db = client["db_streamlit_users"]
    users_collection = db["users"]
    user_data_collection = db["user_data"]
else:
    st.stop()

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def blowfish_encrypt(data: str, password: str) -> str:
    bs = Blowfish.block_size
    key = hashlib.sha256(password.encode()).digest()[:56]  # Blowfish key max 56 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    if isinstance(data, str):
        data = data.encode()
    padded_data = pad(data, bs)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted).decode('utf-8')

def blowfish_decrypt(b64_data: str, password: str) -> str:
    raw = base64.b64decode(b64_data)
    bs = Blowfish.block_size
    key = hashlib.sha256(password.encode()).digest()[:56]
    iv = raw[:bs]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(raw[bs:]), bs)
    return decrypted.decode('utf-8')

def save_encrypted_data(username, data_type, original_name, encrypted_data):
    blowfish_password = "my_secret_key"
    double_encrypted = blowfish_encrypt(encrypted_data, blowfish_password)
    entry = {
        "username":username, 
        "type" : data_type,
        "original_name": original_name, 
        "encrypted_data" : double_encrypted,
        "timestamp" : datetime.now()
    }
    user_data_collection.insert_one(entry)

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = ""
if 'show_register' not in st.session_state:
    st.session_state['show_register'] = False


# Rail Fence + AES

PBKDF2_ITERATIONS = 200000
SALT_SIZE = 16
NONCE_SIZE = 12

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

def derive_key_aes(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

def aes_encrypt(plaintext: str, password: str) -> str:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key_aes(password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(to_bytes(plaintext))
    data = salt + nonce + tag + ciphertext
    return base64.b64encode(data).decode('utf-8')

def aes_decrypt(b64_payload: str, password: str) -> str:
    try:
        data = base64.b64decode(b64_payload)
        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + 16]
        ciphertext = data[SALT_SIZE + NONCE_SIZE + 16:]
        key = derive_key_aes(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return to_str(plaintext)
    except Exception:
        raise ValueError('AES decryption failed.')

def super_encrypt(plaintext: str, rail_key: int, aes_password: str) -> str:
    rf = rail_fence_encrypt(plaintext, rail_key)
    aes = aes_encrypt(rf, aes_password)
    return aes

def super_decrypt(ciphertext_b64: str, rail_key: int, aes_password: str) -> str:
    rf_plain = aes_decrypt(ciphertext_b64, aes_password)
    plain = rail_fence_decrypt(rf_plain, rail_key)
    return plain


# LSB

def encode_lsb(image, message):
    img = image.convert("RGB")
    width, height = img.size
    pixels = img.load()
    binary_message = ''.join(format(ord(c), '08b') for c in message)
    msg_len = len(binary_message)
    if msg_len > width * height * 3:
        st.error("❌ Pesan terlalu panjang untuk gambar ini.")
        return None
    data_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            if data_index < msg_len:
                r = (r & ~1) | int(binary_message[data_index])
                data_index += 1
                if data_index < msg_len:
                    g = (g & ~1) | int(binary_message[data_index])
                    data_index += 1
                if data_index < msg_len:
                    b = (b & ~1) | int(binary_message[data_index])
                    data_index += 1
            pixels[x, y] = (r, g, b)
            if data_index >= msg_len:
                break
        if data_index >= msg_len:
            break
    return img

def decode_lsb(image):
    img = image.convert("RGB")
    width, height = img.size
    pixels = img.load()
    binary_data = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
    chars = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    message = ""
    for c in chars:
        message += chr(int(c, 2))
        if message.endswith("###END###"):
            break
    return message.replace("###END###", "")

# 3DES
MAGIC = b"2DESFILE"
SALT_SIZE_3DES = 16
IV_SIZE = 8
KEY_LEN_3DES = 24
PBKDF2_ITER = 200_000

def derive_key_3des(password: str, salt: bytes):
    if isinstance(password, str):
        password = password.encode("utf-8")
    key = PBKDF2(password, salt, dkLen=KEY_LEN_3DES, count=PBKDF2_ITER)
    try:
        from Crypto.Cipher import DES3 as _DES3
        key = _DES3.adjust_key_parity(key)
    except Exception:
        pass
    return key

def encrypt_data(file_data: bytes, password: str):
    salt = get_random_bytes(SALT_SIZE_3DES)
    iv = get_random_bytes(IV_SIZE)
    key = derive_key_3des(password, salt)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(file_data, DES3.block_size)
    ciphertext = cipher.encrypt(padded)
    return MAGIC + salt + iv + ciphertext

def decrypt_data(file_data: bytes, password: str):
    if not file_data.startswith(MAGIC):
        raise ValueError("File tidak valid atau bukan hasil enkripsi dari program ini.")
    offset = len(MAGIC)
    salt = file_data[offset:offset + SALT_SIZE_3DES]
    iv = file_data[offset + SALT_SIZE_3DES:offset + SALT_SIZE_3DES + IV_SIZE]
    ciphertext = file_data[offset + SALT_SIZE_3DES + IV_SIZE:]
    key = derive_key_3des(password, salt)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    plaintext = unpad(padded, DES3.block_size)
    return plaintext


# Main Dashboard

def main_app():
    st.sidebar.title("👤 Pengguna")
    st.sidebar.write(f"Username: **{st.session_state['username']}**")
    if st.sidebar.button("Keluar 🚪"):
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        st.rerun()

    st.title("🔐 Aplikasi Keamanan Data Lengkap")
    pilihan = st.sidebar.radio("Pilih fitur:", [
        "🧩 LSB Steganografi",
        "🔐 Enkripsi File (3DES)",
        "🌀 Super Enkripsi (Rail Fence + AES)"
    ])

    if pilihan == "🧩 LSB Steganografi":
        st.header("🖼️ LSB Image Steganography")

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🔏 Encode Pesan ke Gambar")
            image_file = st.file_uploader("Upload gambar (PNG/JPG)", type=["png", "jpg", "jpeg"])
            message = st.text_area("Masukkan pesan yang ingin disembunyikan")
            if image_file and message:
                image = Image.open(image_file)
                st.image(image, caption="Gambar Asli", use_container_width=True)
                if st.button("Encode Pesan"):
                    encoded_img = encode_lsb(image, message + "###END###")
                    if encoded_img:
                        st.image(encoded_img, caption="Gambar Hasil Encode", use_container_width=True)
                        buffer = io.BytesIO()
                        encoded_img.save(buffer, format="PNG")
                        buffer.seek(0)
                        encoded_b64 = base64.b64encode(buffer.read()).decode("utf-8")
                        save_encrypted_data(
                            st.session_state["username"],
                            "lsb",
                            image_file.name,
                            encoded_b64
                        )
                        st.success("✅ Gambar terenkripsi disimpan ke database!")
                        st.download_button("💾 Download Gambar Encode", data=base64.b64decode(encoded_b64), file_name="encoded_image.png")
                        # encoded_img.save("encoded_image.png")
                        # with open("encoded_image.png", "rb") as file:
                        #     st.download_button("💾 Download Gambar Encode", data=file, file_name="encoded_image.png")

        with col2:
            st.subheader("🔓 Decode Pesan dari Gambar")
            decode_file = st.file_uploader("Upload gambar hasil encode", type=["png", "jpg", "jpeg"], key="decode_file")
            if decode_file:
                image = Image.open(decode_file)
                st.image(image, caption="Gambar untuk Decode", use_container_width=True)
                if st.button("Decode Pesan"):
                    message = decode_lsb(image)
                    st.text_area("Pesan tersembunyi:", value=message, height=200)

    elif pilihan == "🔐 Enkripsi File (3DES)":
        st.header("🔐 Enkripsi & Dekripsi File (Triple DES)")
        mode = st.radio("Pilih mode:", ["Encrypt", "Decrypt"])
        uploaded_file = st.file_uploader("Unggah file", type=None)
        password = st.text_input("Masukkan password:", type="password")
        if uploaded_file and password:
            file_bytes = uploaded_file.read()
            if st.button("🔄 Jalankan"):
                try:
                    if mode == "Encrypt":
                        result = encrypt_data(file_bytes, password)
                        file_name = uploaded_file.name + ".enc"
                        save_encrypted_data(
                            st.session_state["username"], 
                            "3des",
                            uploaded_file.name,
                            base64.b64encode(result).decode("utf-8")
                        )
                        st.success("✅ File berhasil dienkripsi dan disimpan pada database!")
                    else:
                        result = decrypt_data(file_bytes, password)
                        file_name = uploaded_file.name.replace(".enc", "_decrypted")
                        st.success("✅ File berhasil didekripsi!")
                    st.download_button("💾 Unduh Hasil", result, file_name=file_name)
                except Exception as e:
                    st.error(f"❌ Terjadi kesalahan: {e}")

    elif pilihan == "🌀 Super Enkripsi (Rail Fence + AES)":
        st.header("🌀 Super Enkripsi (Rail Fence + AES)")
        st.subheader("🧩 Enkripsi")
        plaintext = st.text_area("Masukkan teks yang ingin dienkripsi", height=160)
        rail_key_enc = st.number_input("Kunci Rail Fence", min_value=2, max_value=50, value=3, step=1)
        aes_password_enc = st.text_input("Password AES", type="password")
        if st.button("🔐 Enkripsi Sekarang"):
            try:
                result = super_encrypt(plaintext, int(rail_key_enc), aes_password_enc)
                save_encrypted_data(
                    st.session_state["username"],
                    "super_encrypt",
                    "text_message",
                    result
                )
                st.success("✅ Berhasil mengenkripsi!")
                st.code(result)
                st.download_button('Download Ciphertext', result, file_name='ciphertext.txt')
            except Exception as e:
                st.error(f"Gagal mengenkripsi: {e}")

        st.subheader("🔓 Dekripsi")
        ciphertext_b64 = st.text_area("Masukkan ciphertext (base64)", height=160)
        rail_key_dec = st.number_input("Kunci Rail Fence Dekripsi", min_value=2, max_value=50, value=3, step=1)
        aes_password_dec = st.text_input("Password AES Dekripsi", type="password")
        if st.button("🔍 Dekripsi Sekarang"):
            try:
                plaintext = super_decrypt(ciphertext_b64.strip(), int(rail_key_dec), aes_password_dec)
                st.success("✅ Berhasil mendekripsi!")
                st.text_area("Hasil Dekripsi:", value=plaintext, height=200)
            except Exception as e:
                st.error(str(e))


# Login / Register Page

def login_register_page():
    if st.session_state['show_register']:
        st.title("📝 Daftar Akun Baru")
        new_user = st.text_input("Username")
        new_pass = st.text_input("Password", type="password")
        if st.button("Daftar"):
            if not new_user or not new_pass:
                st.warning("Isi semua kolom.")
            elif users_collection.find_one({"username": new_user}):
                st.error("Username sudah digunakan.")
            else:
                users_collection.insert_one({
                    "username": new_user,
                    "password": hash_password(new_pass)
                })
                st.success("Akun berhasil dibuat!")
                st.session_state['show_register'] = False
                st.rerun()
        if st.button("🔑 Sudah punya akun? Masuk"):
            st.session_state['show_register'] = False
            st.rerun()
    else:
        st.title("🔐 Masuk ke Akun Anda")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Masuk"):
            user = users_collection.find_one({
                "username": username,
                "password": hash_password(password)
            })
            if user:
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.success(f"Selamat datang, {username}!")
                st.rerun()
            else:
                st.error("Username atau password salah.")
        if st.button("📝 Belum punya akun? Daftar"):
            st.session_state['show_register'] = True
            st.rerun()


# main run

st.set_page_config(page_title="Keamanan Data Lengkap", page_icon="🔐", layout="wide")

if st.session_state['logged_in']:
    main_app()
else:
    login_register_page()
