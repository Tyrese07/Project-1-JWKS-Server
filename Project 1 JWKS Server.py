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

# Serialize keys to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Create JWKS (JSON Web Key Set) with a key ID (kid)
jwks = {
    "keys": [
        {
            "kid": "my-key-id",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": public_key.public_numbers().n,
            "e": public_key.public_numbers().e,
            "exp": int((datetime.utcnow() + timedelta(minutes=15)).timestamp())  # Key expires in 15 minutes
        }
    ]
}

# Endpoint to serve JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def serve_jwks():
    return jsonify(jwks)

# Authentication endpoint to issue JWTs
@app.route('/auth', methods=['POST'])
def authenticate_and_issue_jwt():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Mock user authentication 
    if username == "userABC" and password == "password123":
        key_id = request.args.get('kid')  # Check for kid query parameter

        # Find the key associated with the provided kid
        key = next((k for k in jwks['keys'] if k['kid'] == key_id), None)

        if key:
            # Generate a JWT with the selected key
            now = datetime.utcnow()
            payload = {
                "sub": username,
                "iat": now,
                "exp": now + timedelta(minutes=15),
                "iss": "your-issuer",
                "aud": "your-audience",
                "kid": key['kid']
            }
            token = jwt.encode(payload, private_pem, algorithm='RS256')

            return jsonify(token=token.decode('utf-8'))

    return "Authentication failed", 401

if __name__ == '__main__':
    app.run(port=8080)
