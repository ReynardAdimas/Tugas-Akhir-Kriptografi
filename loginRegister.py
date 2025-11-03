import streamlit as st
import pymongo
import hashlib

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
    """Meng-hash password menggunakan SHA256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ""

def main_app():
    """Tampilan aplikasi utama setelah user berhasil login."""
    st.sidebar.success(f"Anda masuk sebagai: **{st.session_state['username']}**")
    st.title("🚀 Halaman Utama Aplikasi Anda")
    st.write("Selamat datang di aplikasi utama!")
    st.write("Anda hanya bisa melihat halaman ini setelah berhasil login.")
    
    if st.sidebar.button("Keluar"):
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        st.rerun() 

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
                    hashed_pass_input = hash_password(password)
                    
                    user = users_collection.find_one({"username": username, "password": hashed_pass_input})
                    
                    if user:
                        st.success(f"Selamat datang kembali, {username}!")                
                        st.session_state['logged_in'] = True
                        st.session_state['username'] = username                    
                        st.rerun()
                    else:
                        st.error("Username atau Password yang Anda masukkan salah.")

if st.session_state['logged_in']:
    main_app()
else:
    login_register_page()