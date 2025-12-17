from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import hashlib
import base64
import json

app = Flask(__name__)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')


@app.route('/api/public-key', methods=['GET'])
def get_public_key():
    return jsonify({
        'public_key': public_key_pem
    }), 200


@app.route('/api/send-message', methods=['POST'])
def receive_message():
    try:
        payload = request.get_data(as_text=True)
        print("Step 1: Received encrypted message")

        data = json.loads(payload)

        encrypted_key_b64 = data['encrypted_key']
        encrypted_msg_b64 = data['encrypted_message']
        iv_b64 = data['iv']
        hmac_signature = data['hmac']

        encrypted_key = base64.b64decode(encrypted_key_b64)
        encrypted_msg = base64.b64decode(encrypted_msg_b64)
        iv = base64.b64decode(iv_b64)

        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Step 2: Decrypted AES session key with RSA private key")

        expected_hmac = hmac.new(
            symmetric_key,
            encrypted_msg,
            hashlib.sha256
        ).digest()

        expected_hmac_b64 = base64.b64encode(expected_hmac).decode('utf-8')

        if not hmac.compare_digest(expected_hmac_b64, hmac_signature):
            return jsonify({
                'status': 'error',
                'message': 'HMAC verification failed - message tampered'
            }), 400
        print("Step 3: Verified HMAC signature - message not tampered")

        cipher = Cipher(
            algorithms.AES(symmetric_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_msg = decryptor.update(encrypted_msg) + decryptor.finalize()

        padding_length = decrypted_msg[-1]
        decrypted_msg = decrypted_msg[:-padding_length]
        print("Step 4: Decrypted message content with AES-256-CBC")

        decrypted_text = decrypted_msg.decode('utf-8')
        msg_data = json.loads(decrypted_text)

        print(f"\nMessage from {msg_data['student_name']}")
        print(f"Message: {msg_data['content']}")

        return jsonify({
            'status': 'success',
            'message': 'Message received and verified',
            'received_data': msg_data
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Server error: {str(e)}'
        }), 500


if __name__ == '__main__':
    print("\nSECURE MESSAGING SERVER")
    print("=" * 50)
    print("RSA Key Pair Generated (2048-bit)")
    print("Server running on http://localhost:5000")
    print("Listening for encrypted messages...\n")
    app.run(debug=False, port=5000, use_reloader=False)