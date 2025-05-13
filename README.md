# Image-Assisted Text Encryption Using OFB Mode AES and Pixel Packing

This project implements a text encryption service using OpenAI's GPT model and Flask. The encryption method integrates image-assisted text transformation using AES in OFB (Output Feedback) mode and pixel packing logic.

## 📦 Features

- Accepts a POST request with a text prompt
- Uses OpenAI's ChatCompletion API for processing
- Streams the response back to the user
- Flask-based web server

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

### 4. Set Your OpenAI API Key

Set your API key as an environment variable:

```bash
export OPENAI_API_KEY=your_openai_api_key_here    # On Windows use: set OPENAI_API_KEY=your_openai_api_key_here
```

### 5. Run the Application

```bash
python "test (1).py"
```

The server will start on `http://127.0.0.1:5000`.

---

## 🧪 Testing the Endpoint

You can use `curl` or Postman:

```bash
curl -X POST http://127.0.0.1:5000/encrypt      -H "Content-Type: application/json"      -d '{"prompt": "Encrypt this message using image-assisted AES."}'
```

---
