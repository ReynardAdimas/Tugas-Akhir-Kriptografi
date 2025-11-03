import streamlit as st
import pymongo
import hashlib

# --- KONEKSI KE MONGODB ---

# Menggunakan st.cache_resource untuk memastikan koneksi hanya dibuat sekali
@st.cache_resource
def init_connection():
    try:
        # GANTI DENGAN KONEKSI STRING MONGODB ATLAS ANDA
        # Pastikan IP Anda sudah di-whitelist di MongoDB Atlas
        CONNECTION_STRING = "mongodb+srv://<username>:<password>@<cluster-url>/<db_name>?retryWrites=true&w=majority"
        
        client = pymongo.MongoClient(CONNECTION_STRING)
        # Ping untuk konfirmasi koneksi
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

# Jika koneksi berhasil, ambil database dan koleksi
if client:
    db = client.get_database("db_streamlit_users") # Ganti 'db_streamlit_users' dengan nama db Anda
    users_collection = db.get_collection("users")
else:
    st.stop() # Hentikan eksekusi jika koneksi gagal

# --- FUNGSI HASHING PASSWORD ---

def hash_password(password):
    """Meng-hash password menggunakan SHA256."""
    # Mengubah password menjadi bytes dan meng-hash-nya
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# --- INISIALISASI SESSION STATE ---

# Kita gunakan session state untuk melacak status login pengguna
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ""

# --- FUNGSI UTAMA APLIKASI ---

def main_app():
    """Tampilan aplikasi utama setelah user berhasil login."""
    st.sidebar.success(f"Anda masuk sebagai: **{st.session_state['username']}**")
    st.title("🚀 Halaman Utama Aplikasi Anda")
    st.write("Selamat datang di aplikasi utama!")
    st.write("Anda hanya bisa melihat halaman ini setelah berhasil login.")
    
    if st.sidebar.button("Keluar"):
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        st.rerun() # Muat ulang aplikasi untuk kembali ke halaman login

def login_register_page():
    """Tampilan untuk login dan register."""
    st.title("Selamat Datang!")
    st.sidebar.image("https://streamlit.io/images/brand/streamlit-logo-primary-col.png", width=200)
    
    menu = ["Masuk (Login)", "Daftar (Register)"]
    choice = st.sidebar.selectbox("Pilih Menu", menu)

    if choice == "Daftar (Register)":
        st.subheader("Buat Akun Baru")
        
        with st.form("Form Pendaftaran"):
            new_user = st.text_input("Username", key="reg_user")
            new_pass = st.text_input("Password", type="password", key="reg_pass")
            submit_button = st.form_submit_button(label="Daftar")

            if submit_button:
                if not new_user or not new_pass:
                    st.warning("Username dan Password tidak boleh kosong.")
                else:
                    # Cek apakah username sudah ada
                    if users_collection.find_one({"username": new_user}):
                        st.error("Username ini sudah terdaftar. Silakan gunakan username lain.")
                    else:
                        # Hash password
                        hashed_pass = hash_password(new_pass)
                        # Simpan ke database
                        users_collection.insert_one({"username": new_user, "password": hashed_pass})
                        st.success("Akun Anda berhasil dibuat!")
                        st.info("Silakan pindah ke menu 'Masuk (Login)' untuk masuk.")

    elif choice == "Masuk (Login)":
        st.subheader("Masuk ke Akun Anda")
        
        with st.form("Form Login"):
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")
            login_button = st.form_submit_button(label="Masuk")

            if login_button:
                if not username or not password:
                    st.warning("Username dan Password tidak boleh kosong.")
                else:
                    # Hash password yang diinput
                    hashed_pass_input = hash_password(password)
                    
                    # Cari user di database
                    user = users_collection.find_one({"username": username, "password": hashed_pass_input})
                    
                    if user:
                        st.success(f"Selamat datang kembali, {username}!")
                        # Set session state
                        st.session_state['logged_in'] = True
                        st.session_state['username'] = username
                        # Muat ulang aplikasi untuk masuk ke halaman utama
                        st.rerun()
                    else:
                        st.error("Username atau Password yang Anda masukkan salah.")

# --- KONTROL TAMPILAN (GATEKEEPER) ---

if st.session_state['logged_in']:
    main_app()
else:
    login_register_page()