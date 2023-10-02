from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize public key to PEM format for JWK
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Create JWK (JSON Web Key)
jwk = {
    "kid": "my-key-id",
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "n": public_key.public_numbers().n,
    "e": public_key.public_numbers().e
}

# Endpoint to serve JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def serve_jwks():
    return jsonify(keys=[jwk])

# Authentication endpoint to issue JWTs
@app.route('/auth', methods=['POST'])
def authenticate_and_issue_jwt():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Mock user authentication 
    if username == "userABC" and password == "password123":
        # Generate a Key ID (kid)
        key_id = "0d1f0f0cfbd8216a3a0d1f0f0cfbd8216a3a0d1f0f0cfbd8216a3a0d1f0f0cfbd"

        # Generate a JWT with the selected key
        now = datetime.utcnow()
        payload = {
            "sub": username,
            "iat": now,
            "exp": now + timedelta(minutes=15),
            "iss": "my-app",
            "aud": "api-server",
            "kid": key_id
        }
        token = jwt.encode(payload, private_key, algorithm='RS256')

        # Return the token as plain text
        return token.decode('utf-8')

    return "Authentication failed", 401

if __name__ == '__main__':
    app.run(port=8080)
