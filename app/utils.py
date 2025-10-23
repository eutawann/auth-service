import base64

def generate_token(email: str, doc_number: str) -> str:
    token_data = f"{email}:{doc_number}"
    token_base64 = base64.b64encode(token_data.encode('utf-8')).decode('utf-8')
    return token_base64