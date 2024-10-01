import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_keys():
    # Generate RSA keys for the client
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
     # Create a hash object and update it with the public key bytes
    hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_obj.update(public_pem)
    fingerprint = base64.b64encode(hash_obj.finalize()).decode('utf-8')
    return private_key, public_pem ,fingerprint

def verify_signature(public_key, data_json, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            data_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32  # Ensure this salt length is used
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False