from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import dotenv
import mysql.connector
import hashlib
import os

app = Flask(__name__)

dotenv.load_dotenv()

HOST = os.getenv("HOST")
USER = os.getenv("USER")
PASS = os.getenv("PASS")
DB = os.getenv("DB")

with open("private_key.pem", "rb") as priv_file:
    private_key_data = priv_file.read()
    private_key = serialization.load_pem_private_key(
        private_key_data, password=None, backend=default_backend()
    )

with open("public_key.pem", "rb") as pub_file:
    public_key_data = pub_file.read()
    public_key = serialization.load_pem_public_key(
        public_key_data, backend=default_backend()
    )

db_config = {
    "host": HOST,
    "user": USER,
    "password": PASS,
    "database": DB,
}


def generate_key_hash(signature):
    hash_obj = hashlib.sha256(signature)
    hashed_signature = hash_obj.hexdigest()
    license_parts = [
        hashed_signature[i : i + 4].upper() for i in range(0, len(hashed_signature), 4)
    ]
    return "-".join(license_parts[:4])


@app.route("/generate_key", methods=["POST"])
def generate_key():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email not provided"}), 400

    signature = private_key.sign(
        email.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    license_key = generate_key_hash(signature)

    return jsonify({"license_key": license_key})


@app.route("/verify_key", methods=["POST"])
def verify_key():
    data = request.json

    email = data["email"]
    provided_key = data["license_key"]

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    query = "SELECT COUNT(*) FROM your_table_name WHERE email = %s AND key = %s"
    cursor.execute(query, (email, provided_key))
    count = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    if count > 0:
        return jsonify(valid=True)
    else:
        return jsonify(valid=False)


if __name__ == "__main__":
    app.run(debug=True)
