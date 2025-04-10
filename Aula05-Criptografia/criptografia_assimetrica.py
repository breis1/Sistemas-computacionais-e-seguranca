"""
Criptografia Assimétrica com RSA
Utiliza um par de chaves: uma pública para criptografar e uma privada para descriptografar.
"""
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()) #Expoente público usado na matemática da chave RSA e tamanho da chave 2.048 bits (~256 bytes)
    public_key = private_key.public_key() #derivada da chave privada, são matematicamente conectadas, mas é impossível descobrir uma a partir da outra
    return private_key, public_key

def encrypt_rsa(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(), #A mensagem é convertida para bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_rsa(ciphertext, private_key):
    decoded = base64.b64decode(ciphertext)
    return private_key.decrypt(
        decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

if __name__ == "__main__":
    mensagem = "Mensagem de teste para criptografia assimétrica."
    chave_privada, chave_publica = generate_rsa_keys()
    criptografado = encrypt_rsa(mensagem, chave_publica)
    print("Criptografado:", criptografado)
    descriptografado = decrypt_rsa(criptografado, chave_privada)
    print("Descriptografado:", descriptografado)
