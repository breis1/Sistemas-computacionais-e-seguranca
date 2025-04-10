"""
Função Hash com SHA-256
Transforma a mensagem original em um código fixo e irreversível.
Ideal para verificação de integridade.
Se você colocar qualquer tamanho de texto, ele vai sair com um hash de 256 bits (64 chars).
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_hash(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode())
    return digest.finalize().hex()

if __name__ == "__main__":
    mensagem = "Mensagem de teste para função hash."
    hash_resultado = generate_hash(mensagem)
    print("Hash SHA-256:", hash_resultado)
