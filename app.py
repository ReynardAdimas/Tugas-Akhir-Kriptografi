import streamlit as st 
from PIL import Image 

def encode_lsb(image, message):
    img = image.convert("RGB")
    width, height = img.size
    pixels = img.load() 

    # pesan jadi biner 
    binary_message = ''.join(format(ord(c), '08b') for c in message)
    msg_len = len(binary_message)

    if msg_len > width * height * 3:
        st.error("Pesan terlalu panjang untuk gambar ini") 
        return None 
    
    data_index = 0 
    for y in range(height):
        for x in range(width):
            r,g,b = pixels[x,y] 

            # ubah bit terakhir tiap channel 
            if data_index < msg_len:
                r = (r & ~1) | int(binary_message[data_index])
                data_index += 1 
                g = (g & ~1) | int(binary_message[data_index])
                data_index += 1 
                b = (b & ~1) | int(binary_message[data_index])
                data_index += 1 
            pixels[x,y] = (r,g,b) 
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
            r,g,b = pixels[x,y] 
            binary_data += str(r&1)
            binary_data += str(g&1)
            binary_data += str(b&1) 
    # mengubah tiap 8 bit jadi ascii 
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)] 
    message = ""
    for c in chars:
        message += chr(int(c,2))
        if message.endswith("###END###"):
            break
    return message.replace("###END###", "") 

st.title("🖼️ LSB Image Steganography with Streamlit")

tab1, tab2 = st.tabs(["🔐 Encode", "🔓 Decode"])

# ----------- ENCODE -----------
with tab1:
    st.header("Sembunyikan Pesan ke Gambar")

    image_file = st.file_uploader("Upload gambar", type=["png", "jpg", "jpeg"])
    message = st.text_area("Masukkan pesan yang ingin disembunyikan")

    if image_file and message:
        image = Image.open(image_file)
        st.image(image, caption="Gambar Asli", use_container_width=True)

        if st.button("Encode Pesan"):
            encoded_img = encode_lsb(image, message + "###END###")
            if encoded_img:
                st.image(encoded_img, caption="Gambar dengan Pesan", use_container_width=True)
                encoded_img.save("encoded_image.png")
                with open("encoded_image.png", "rb") as file:
                    st.download_button("💾 Download Hasil Encode", data=file, file_name="encoded_image.png")

# ----------- DECODE -----------
with tab2:
    st.header("Ambil Pesan dari Gambar")

    decode_file = st.file_uploader("Upload gambar hasil encode", type=["png", "jpg", "jpeg"], key="decode_file")
    if decode_file:
        image = Image.open(decode_file)
        st.image(image, caption="Gambar untuk Decode", use_container_width=True)

        if st.button("Decode Pesan"):
            message = decode_lsb(image)
            st.text_area("Pesan tersembunyi:", value=message, height=200)

