from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os

app = Flask(__name__)
CORS(app)

# Configuration for SQLite
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///license.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True

db = SQLAlchemy(app)


class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    key = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


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

    new_license = License(email=email, key=license_key)
    db.session.add(new_license)
    db.session.commit()

    return jsonify({"license_key": license_key})


@app.route("/verify_key", methods=["POST"])
def verify_key():
    data = request.json
    email = data["email"]
    provided_key = data["license_key"]

    license_record = License.query.filter_by(email=email, key=provided_key).first()

    return jsonify(valid=bool(license_record))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
