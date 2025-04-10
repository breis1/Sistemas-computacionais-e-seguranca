"""
Criptografia Simétrica com AES (Advanced Encryption Standard)
Utiliza a mesma chave para criptografar e descriptografar.

Rápida e eficiente, ideal para grandes volumes de dados.

A criptografia é feita em modo CFB (Cipher Feedback), que permite criptografar dados de tamanho variável.

Um IV (vetor de inicialização) aleatório é usado para tornar cada criptografia única, mesmo com a mesma chave e mensagem.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_aes(message, key):
    iv = os.urandom(16)  # Vetor de inicialização para o modo CFB
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt_aes(encrypted_message, key):
    raw = base64.b64decode(encrypted_message)
    iv = raw[:16]  # Extrai o IV do início
    ct = raw[16:]  # Resto é o conteúdo criptografado
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

if __name__ == "__main__":
    mensagem = "Mensagem de teste para criptografia simétrica."
    chave = os.urandom(32)  # Chave de 256 bits
    criptografado = encrypt_aes(mensagem, chave)
    print("Criptografado:", criptografado)
    descriptografado = decrypt_aes(criptografado, chave)
    print("Descriptografado:", descriptografado)
