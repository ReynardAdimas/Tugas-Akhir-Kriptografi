import streamlit as st
import pymongo
import hashlib
import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

@st.cache_resource
def init_connection():
    try:
        CONNECTION_STRING = "mongodb://localhost:27017/"
        client = pymongo.MongoClient(CONNECTION_STRING)
        client.admin.command('ping')
        st.success("Berhasil terhubung ke MongoDB!", icon="✅")
        return client
    except pymongo.errors.ConnectionFailure as e:
        st.error(f"Koneksi ke MongoDB gagal: {e}", icon="❌")
        return None
    except Exception as e:
        st.error(f"Terjadi kesalahan: {e}", icon="❌")
        return None

client = init_connection()

if client:
    db = client.get_database("db_streamlit_users")
    users_collection = db.get_collection("users")
else:
    st.stop()

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = ""
if 'show_register' not in st.session_state:
    st.session_state['show_register'] = False

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

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

def aes_encrypt(plaintext: str, password: str) -> str:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
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
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return to_str(plaintext)
    except Exception:
        raise ValueError('AES decryption failed. Pastikan password benar dan input tidak korup.')

def super_encrypt(plaintext: str, rail_key: int, aes_password: str) -> str:
    rf = rail_fence_encrypt(plaintext, rail_key)
    aes = aes_encrypt(rf, aes_password)
    return aes

def super_decrypt(ciphertext_b64: str, rail_key: int, aes_password: str) -> str:
    rf_plain = aes_decrypt(ciphertext_b64, aes_password)
    plain = rail_fence_decrypt(rf_plain, rail_key)
    return plain

def main_app():
    st.sidebar.title("👤 Pengguna")
    st.sidebar.write(f"Username: **{st.session_state['username']}**")
    if st.sidebar.button("Keluar 🚪"):
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        st.rerun()

    st.title("🔒 Super Enkripsi & Dekripsi (Rail Fence + AES)")
    st.markdown("---")

    st.subheader("🧩 Enkripsi")
    plaintext = st.text_area("Masukkan teks yang ingin dienkripsi", height=160)
    rail_key_enc = st.number_input("Kunci Rail Fence (angka)", min_value=2, max_value=50, value=3, step=1)
    aes_password_enc = st.text_input("Password AES", type="password")

    if st.button("🔐 Enkripsi Sekarang"):
        if plaintext.strip() == "":
            st.warning("Masukkan teks yang ingin dienkripsi.")
        elif aes_password_enc.strip() == "":
            st.warning("Masukkan password AES.")
        else:
            try:
                result = super_encrypt(plaintext, int(rail_key_enc), aes_password_enc)
                st.success("✅ Berhasil mengenkripsi!")
                st.code(result, language='text')
                st.download_button('Download Ciphertext', result, file_name='ciphertext.txt')
            except Exception as e:
                st.error(f"Gagal mengenkripsi: {e}")

    st.markdown("---")

    st.subheader("🔓 Dekripsi")
    ciphertext_b64 = st.text_area("Masukkan ciphertext (base64)", height=160)
    rail_key_dec = st.number_input("Kunci Rail Fence untuk Dekripsi", min_value=2, max_value=50, value=3, step=1)
    aes_password_dec = st.text_input("Password AES untuk Dekripsi", type="password")

    if st.button("🔍 Dekripsi Sekarang"):
        if ciphertext_b64.strip() == "":
            st.warning("Masukkan ciphertext base64 terlebih dahulu.")
        elif aes_password_dec.strip() == "":
            st.warning("Masukkan password AES.")
        else:
            try:
                plaintext = super_decrypt(ciphertext_b64.strip(), int(rail_key_dec), aes_password_dec)
                st.success("✅ Berhasil mendekripsi!")
                st.text_area("Hasil Dekripsi:", value=plaintext, height=200)
            except ValueError as ve:
                st.error(str(ve))
            except Exception:
                st.error("Gagal mendekripsi. Pastikan password, kunci, dan ciphertext benar.")

def login_register_page():
    if st.session_state['show_register']:
        st.title("📝 Daftar Akun Baru")
        with st.form("FormRegister"):
            new_user = st.text_input("Username")
            new_pass = st.text_input("Password", type="password")
            submit_button = st.form_submit_button("Daftar")
            if submit_button:
                if not new_user or not new_pass:
                    st.warning("Username dan Password tidak boleh kosong.")
                elif users_collection.find_one({"username": new_user}):
                    st.error("Username sudah terdaftar. Gunakan nama lain.")
                else:
                    hashed_pass = hash_password(new_pass)
                    users_collection.insert_one({"username": new_user, "password": hashed_pass})
                    st.success("Akun berhasil dibuat! Silakan login.")
                    st.session_state['show_register'] = False
                    st.rerun()
        st.markdown("<hr>", unsafe_allow_html=True)
        if st.button("🔑 Sudah punya akun? Masuk di sini"):
            st.session_state['show_register'] = False
            st.rerun()
    else:
        st.title("🔐 Masuk ke Akun Anda")
        with st.form("FormLogin"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_button = st.form_submit_button("Masuk")
            if login_button:
                if not username or not password:
                    st.warning("Username dan Password tidak boleh kosong.")
                else:
                    hashed_input = hash_password(password)
                    user = users_collection.find_one({"username": username, "password": hashed_input})
                    if user:
                        st.session_state['logged_in'] = True
                        st.session_state['username'] = username
                        st.success(f"Selamat datang, {username}!")
                        st.rerun()
                    else:
                        st.error("Username atau Password salah.")
        st.markdown("<hr>", unsafe_allow_html=True)
        if st.button("📝 Belum punya akun? Daftar di sini"):
            st.session_state['show_register'] = True
            st.rerun()

if st.session_state['logged_in']:
    main_app()
else:
    login_register_page()
