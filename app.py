import streamlit as st
from PIL import Image
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# LSB Section
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


# 3DES Section
MAGIC = b"2DESFILE"
SALT_SIZE = 16
IV_SIZE = 8
KEY_LEN_3DES = 24
PBKDF2_ITER = 200_000


def derive_key(password: str, salt: bytes, key_len: int = KEY_LEN_3DES):
    if isinstance(password, str):
        password = password.encode("utf-8")
    key = PBKDF2(password, salt, dkLen=key_len, count=PBKDF2_ITER)
    try:
        from Crypto.Cipher import DES3 as _DES3
        key = _DES3.adjust_key_parity(key)
    except Exception:
        pass
    return key


def encrypt_data(file_data: bytes, password: str):
    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE)
    key = derive_key(password, salt, KEY_LEN_3DES)

    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(file_data, DES3.block_size)
    ciphertext = cipher.encrypt(padded)

    return MAGIC + salt + iv + ciphertext


def decrypt_data(file_data: bytes, password: str):
    if not file_data.startswith(MAGIC):
        raise ValueError("File tidak valid atau bukan hasil enkripsi dari program ini.")

    offset = len(MAGIC)
    salt = file_data[offset:offset + SALT_SIZE]
    iv = file_data[offset + SALT_SIZE:offset + SALT_SIZE + IV_SIZE]
    ciphertext = file_data[offset + SALT_SIZE + IV_SIZE:]

    key = derive_key(password, salt, KEY_LEN_3DES)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    plaintext = unpad(padded, DES3.block_size)

    return plaintext

# UI Section
st.set_page_config(page_title="LSB & 3DES App", page_icon="🔐", layout="wide")

st.title("🧩 Steganografi Gambar & Enkripsi File 3DES")
st.write("Aplikasi ini memiliki dua fungsi utama:")
st.markdown("""
1. 🖼️ **Steganografi Gambar (LSB)** — Menyembunyikan pesan teks ke dalam gambar.
2. 🔐 **Enkripsi File (3DES)** — Melindungi file dengan enkripsi Triple DES.
""")

# Stego
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
                encoded_img.save("encoded_image.png")
                with open("encoded_image.png", "rb") as file:
                    st.download_button("💾 Download Gambar Encode", data=file, file_name="encoded_image.png")

with col2:
    st.subheader("🔓 Decode Pesan dari Gambar")
    decode_file = st.file_uploader("Upload gambar hasil encode", type=["png", "jpg", "jpeg"], key="decode_file")
    if decode_file:
        image = Image.open(decode_file)
        st.image(image, caption="Gambar untuk Decode", use_container_width=True)

        if st.button("Decode Pesan"):
            message = decode_lsb(image)
            st.text_area("Pesan tersembunyi:", value=message, height=200)

# 3DES Section
st.markdown("---")
st.header("🔐 Enkripsi & Dekripsi File (Triple DES)")

mode = st.radio("Pilih mode:", ["Encrypt", "Decrypt"])
uploaded_file = st.file_uploader("Unggah file untuk diproses", type=None)
password = st.text_input("Masukkan password:", type="password")

if uploaded_file and password:
    file_bytes = uploaded_file.read()

    if st.button("🔄 Jalankan Enkripsi/Dekripsi"):
        try:
            if mode == "Encrypt":
                result = encrypt_data(file_bytes, password)
                file_name = uploaded_file.name + ".enc"
                st.success("✅ File berhasil dienkripsi!")
            else:
                result = decrypt_data(file_bytes, password)
                file_name = uploaded_file.name.replace(".enc", "_decrypted")
                st.success("✅ File berhasil didekripsi!")

            st.download_button(
                label="💾 Unduh Hasil",
                data=result,
                file_name=file_name,
                mime="application/octet-stream",
            )

        except Exception as e:
            st.error(f"❌ Terjadi kesalahan: {e}")

