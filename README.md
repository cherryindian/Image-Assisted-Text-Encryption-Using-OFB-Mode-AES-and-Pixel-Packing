# Image-Assisted Text Encryption Using OFB Mode AES and Pixel Packing
A Python desktop application that encrypts text messages by first encoding them into an image format and then securing the image using AES encryption in OFB mode. This tool provides a unique, multi-layered approach to text confidentiality.


## 🌟 Overview

This project explores a novel method for text encryption. Instead of directly encrypting plaintext, the message is first transformed into a visual representation by packing its byte data into the pixels of a newly generated image. This intermediate image is then encrypted using the robust AES (Advanced Encryption Standard) algorithm in Output Feedback (OFB) mode. The application provides a user-friendly Tkinter GUI for easy encryption and decryption.

## ✨ Features

* **User-Friendly GUI:** Intuitive interface built with Tkinter for easy operation.
* **Text-to-Image Encoding:** Converts text messages into a temporary image file where message bytes are stored as pixel data (RGB values).
* **AES Encryption:** Secures the generated image file using AES in OFB mode with a user-provided key.
* **Base64 Encoding:** IV and Ciphertext are Base64 encoded for safe storage and transfer.
* **File-Based Encryption/Decryption:** Encrypted messages are saved as `.enc` files.
* **Cross-Platform:** Being Python and Tkinter based, it can run on various operating systems.

## 🛠️ How It Works

### Encryption Process:
1.  **Input:** User provides a text message and an encryption key.
2.  **Key Preparation:** The key is padded to meet AES block size requirements.
3.  **Text-to-Image Encoding:**
    * The input text is converted to UTF-8 bytes.
    * These bytes are packed into RGB values (3 bytes per pixel).
    * A new image is dynamically created with dimensions just large enough to hold these pixels.
    * This image (e.g., `encryptedImage.png`) is saved temporarily.
4.  **Image Encryption (AES-OFB):**
    * The temporary image file is read as binary data.
    * This data is padded and then encrypted using AES in OFB mode with the user's key and a randomly generated Initialization Vector (IV).
    * The IV and the resulting ciphertext are Base64 encoded.
5.  **Output:** The Base64 IV is prepended to the Base64 ciphertext and saved to a user-specified `.enc` file.

### Decryption Process:
1.  **Input:** User selects an `.enc` file and provides the decryption key.
2.  **Key Preparation:** The key is padded as in the encryption process.
3.  **Data Retrieval:** The `.enc` file is read, and the Base64 IV and ciphertext are separated.
4.  **Image Decryption (AES-OFB):**
    * IV and ciphertext are Base64 decoded.
    * The ciphertext is decrypted using AES-OFB with the key and IV.
    * The decrypted binary data (the original image data) is unpadded and saved as a temporary image (e.g., `decrypted_image.png`).
5.  **Image-to-Text Decoding:**
    * The temporary image is loaded.
    * RGB pixel values are extracted and converted back into a byte stream.
    * Trailing null bytes are removed, and the byte stream is decoded (UTF-8) to retrieve the original message.
6.  **Output:** The decrypted message is displayed in the GUI.

## 💻 Technology Stack

* **Python 3.x** (Tested with 3.7+)
* **Tkinter:** For the graphical user interface.
* **Pillow (PIL Fork):** For image creation and manipulation.
* **PyCryptodome:** For AES encryption and utility functions.

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/cherryindian/Image-Assisted-Text-Encryption-Using-OFB-Mode-AES-and-Pixel-Packing.git
cd Image-Assisted-Text-Encryption-Using-OFB-Mode-AES-and-Pixel-Packing
```

### 2. Set Up Python Environment

It's recommended to use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate   # On Windows use: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```



### 4. Run the Application

```bash
python "SecureMessageEncryptor.py"
```


---
