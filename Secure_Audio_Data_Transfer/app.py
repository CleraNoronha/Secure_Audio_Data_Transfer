from flask import Flask, render_template, request, send_file, redirect, url_for
import os
import json
import uuid
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization

from src.crypto import encrypt_hybrid, decrypt_hybrid
from src.stego import (
    build_container,
    parse_container,
    embed_bytes_in_wav,
    extract_bytes_from_wav
)

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
KEY_FOLDER = "keys"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# -------- LOAD KEYS SAFELY --------
def load_keys():
    try:
        with open(os.path.join(KEY_FOLDER, "public.pem"), "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        with open(os.path.join(KEY_FOLDER, "private.pem"), "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        return public_key, private_key

    except Exception as e:
        raise RuntimeError(f"Key loading failed: {e}")


# -------- ROUTES --------
@app.route("/")
def landing():
    try:
        return render_template("home.html")
    except Exception as e:
        return str(e)



@app.route("/app")
def home():
    return render_template("index.html")


# -------- SENDER --------
@app.route("/send", methods=["POST"])
def send_secret():

    public_key, _ = load_keys()

    if "secret" not in request.files or "cover" not in request.files:
        return "Missing files", 400

    secret_file = request.files["secret"]
    cover_audio = request.files["cover"]

    if secret_file.filename == "" or cover_audio.filename == "":
        return "Invalid file", 400

    # Secure filenames
    secret_filename = secure_filename(secret_file.filename)
    cover_filename = secure_filename(cover_audio.filename)

    # Unique filenames
    unique_id = str(uuid.uuid4())
    secret_path = os.path.join(UPLOAD_FOLDER, unique_id + "_" + secret_filename)
    cover_path = os.path.join(UPLOAD_FOLDER, unique_id + "_" + cover_filename)

    secret_file.save(secret_path)
    cover_audio.save(cover_path)

    # File size check
    if os.path.getsize(secret_path) > MAX_FILE_SIZE:
        return "Secret file too large (max 10MB)", 400

    # Encrypt
    with open(secret_path, "rb") as f:
        secret_bytes = f.read()

    encrypted_bundle = encrypt_hybrid(secret_bytes, public_key)
    encrypted_json_bytes = json.dumps(encrypted_bundle).encode("utf-8")

    # Build container
    container = build_container(encrypted_json_bytes)

    # Embed
    stego_filename = unique_id + "_stego.wav"
    stego_path = os.path.join(UPLOAD_FOLDER, stego_filename)

    embed_bytes_in_wav(container, cover_path, stego_path, lsb_count=1)

    return send_file(stego_path, as_attachment=True)


# -------- RECEIVER --------
@app.route("/receive", methods=["POST"])
def receive_secret():

    _, private_key = load_keys()

    if "stego" not in request.files:
        return "Missing stego file", 400

    stego_audio = request.files["stego"]

    if stego_audio.filename == "":
        return "Invalid file", 400

    stego_filename = secure_filename(stego_audio.filename)
    unique_id = str(uuid.uuid4())
    stego_path = os.path.join(UPLOAD_FOLDER, unique_id + "_" + stego_filename)

    stego_audio.save(stego_path)

    # Extract container
    container_bytes = extract_bytes_from_wav(stego_path, lsb_count=1)

    encrypted_json_bytes = parse_container(container_bytes)
    encrypted_bundle = json.loads(encrypted_json_bytes.decode("utf-8"))

    # Decrypt
    original_bytes = decrypt_hybrid(encrypted_bundle, private_key)

    recovered_filename = unique_id + "_recovered_file"
    output_path = os.path.join(UPLOAD_FOLDER, recovered_filename)

    with open(output_path, "wb") as f:
        f.write(original_bytes)

    return send_file(output_path, as_attachment=True)


if __name__ == "__main__":
    app.run()
