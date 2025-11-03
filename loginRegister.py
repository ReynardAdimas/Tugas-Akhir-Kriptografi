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
if 'username' not in st.session_state:
    st.session_state['username'] = ""
if 'show_register' not in st.session_state:
    st.session_state['show_register'] = False  # False = Login, True = Register

def main_app():
    """Tampilan aplikasi utama setelah login."""
    st.title("🚀 Halaman Utama Aplikasi Anda")
    st.success(f"Anda masuk sebagai: **{st.session_state['username']}**")
    st.write("Selamat datang di aplikasi utama!")
    st.write("Anda hanya bisa melihat halaman ini setelah berhasil login.")
    
    if st.button("Keluar"):
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        st.rerun()

def login_register_page():
    """Tampilan login dan register tanpa sidebar."""

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
        st.markdown(
            "<p style='text-align:center;'>Sudah punya akun?</p>",
            unsafe_allow_html=True
        )
        if st.button("Masuk di sini 🔑"):
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
                    user = users_collection.find_one(
                        {"username": username, "password": hashed_input}
                    )
                    if user:
                        st.session_state['logged_in'] = True
                        st.session_state['username'] = username
                        st.success(f"Selamat datang, {username}!")
                        st.rerun()
                    else:
                        st.error("Username atau Password salah.")

        # Tombol pindah ke register
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown(
            "<p style='text-align:center;'>Belum punya akun?</p>",
            unsafe_allow_html=True
        )
        if st.button("Daftar di sini 📝"):
            st.session_state['show_register'] = True
            st.rerun()

if st.session_state['logged_in']:
    main_app()
else:
    login_register_page()
