import requests
import json
import base64
import hmac
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization


class Student:
    def __init__(self, name, student_id, email):
        self.name = name
        self.student_id = student_id
        self.email = email

    def to_dict(self):
        return {
            'student_name': self.name,
            'student_id': self.student_id,
            'student_email': self.email
        }


class SecureMessagingClient:
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
        self.server_public_key = None
        self.student = None
        self.session_key = None

    def fetch_public_key(self):
        try:
            response = requests.get(f'{self.server_url}/api/public-key')
            data = response.json()

            self.server_public_key = serialization.load_pem_public_key(
                data['public_key'].encode('utf-8'),
                backend=default_backend()
            )

            print("Fetched server public key")
            return True
        except Exception as e:
            print(f"Failed to fetch public key: {str(e)}")
            return False

    def initialize_student(self, name, student_id, email):
        self.student = Student(name, student_id, email)
        print(f"Student initialized: {name}")

    def generate_session_key(self):
        self.session_key = os.urandom(32)
        print("Generated AES session key (256-bit)")

    def encrypt_session_key(self):
        encrypted_key = self.server_public_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode('utf-8')

    def encrypt_message(self, message_json):
        iv = os.urandom(16)

        message_bytes = message_json.encode('utf-8')

        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)

        cipher = Cipher(
            algorithms.AES(self.session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        encrypted_msg = encryptor.update(padded_message) + encryptor.finalize()

        return base64.b64encode(encrypted_msg).decode('utf-8'), base64.b64encode(iv).decode('utf-8')

    def compute_hmac(self, encrypted_msg_b64):
        encrypted_msg = base64.b64decode(encrypted_msg_b64)
        hmac_signature = hmac.new(
            self.session_key,
            encrypted_msg,
            hashlib.sha256
        ).digest()
        return base64.b64encode(hmac_signature).decode('utf-8')

    def send_message(self, message_content):
        try:
            if not self.server_public_key:
                print("Server public key not fetched")
                return False

            if not self.student:
                print("Student not initialized")
                return False

            if not self.session_key:
                self.generate_session_key()

            student_data = self.student.to_dict()
            student_data['content'] = message_content
            message_json = json.dumps(student_data)

            print(f"\nSending: {message_content}")
            print(f"JSON created:")
            print(message_json)

            encrypted_key = self.encrypt_session_key()
            print("Encrypted session key with RSA-2048")

            encrypted_msg, iv = self.encrypt_message(message_json)
            print("Encrypted message with AES-256-CBC")

            hmac_sig = self.compute_hmac(encrypted_msg)
            print("Computed HMAC-SHA256 signature")

            payload = {
                'encrypted_key': encrypted_key,
                'encrypted_message': encrypted_msg,
                'iv': iv,
                'hmac': hmac_sig
            }
            print("Encoded payload in Base64")

            response = requests.post(
                f'{self.server_url}/api/send-message',
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                print("Message delivered")
                return True
            else:
                print(f"Server error: {response.json()}")
                return False

        except Exception as e:
            print(f"Error sending message: {str(e)}")
            return False


def main():
    print("\nSECURE MESSAGING CLIENT")
    print("=" * 50)

    client = SecureMessagingClient()

    print("\nStep 1: Fetch server public key")
    if not client.fetch_public_key():
        print("Could not connect to server")
        return

    print("\nStep 2: Initialize student")
    client.initialize_student(
        name="Alice Johnson",
        student_id="STU2024001",
        email="alice@university.edu"
    )

    print("\nStep 3: Send secure messages")
    print("-" * 50)

    messages = [
        "Hello, this is a secure message",
        "All content is encrypted with AES",
        "HMAC ensures data integrity"
    ]

    for msg in messages:
        client.send_message(msg)
        print("-" * 50)

    print("\nAll messages sent\n")


if __name__ == '__main__':
    main()