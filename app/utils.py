import os
import base64
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
import secrets

load_dotenv()

def load_secret_key():
    hex_key = os.getenv("SECRET_KEY")
    if not hex_key or len(hex_key) != 64:
        raise ValueError("SecretKey não encontrada ou com formato inválido")
    
    return bytes.fromhex(hex_key)

try:
    AES_KEY = load_secret_key()
    aesgcm = AESGCM(AES_KEY)
except ValueError as e:
    print(f"Erro ao carregar secret key: {e}")
    
    AES_KEY = None
    aesgcm = None

NONCE_BYTES = 12


def generate_encrypted_token(email: str, doc_number: str) -> str:

    if not aesgcm:
        raise Exception("AESGCM não foi inicializado. Verifique a secretkey")
    
    payload = {
        "email": email,
        "doc_number": doc_number,
        "issuedAt": datetime.now(timezone.utc).timestamp()
    }

    payload_bytes = json.dumps(payload).encode('utf-8')

    nonce = os.urandom(NONCE_BYTES)

    ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)

    token_bytes = nonce + ciphertext

    token_b64 = base64.urlsafe_b64encode(token_bytes).decode('utf-8')

    return token_b64

def decrypt_and_validate_token(token_b64: str) -> dict:
    
    if not aesgcm:
        raise Exception("AESGCM não foi inicializado, verifique a secretkey.")
        
    try:
        token_bytes = base64.urlsafe_b64decode(token_b64.encode('utf-8'))
        nonce = token_bytes[:NONCE_BYTES]
        ciphertext = token_bytes[NONCE_BYTES:]

        payload_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        payload = json.loads(payload_bytes.decode('utf-8'))
        return payload
        
    except Exception as e:

        print(f"Erro ao descriptografar token: {e}")
        return None
    
def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)