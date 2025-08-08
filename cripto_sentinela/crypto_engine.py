import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .utils import b64encode, b64decode


def gerar_chaves():
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ecdsa_priv = ec.generate_private_key(ec.SECP256R1())
    return {
        "rsa_priv": rsa_priv,
        "rsa_pub": rsa_priv.public_key(),
        "ecdsa_priv": ecdsa_priv,
        "ecdsa_pub": ecdsa_priv.public_key()
    }


def exportar_chave(chave, privada=False):
    if privada:
        return b64encode(chave.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    else:
        return b64encode(chave.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def importar_chave_pub(b64_str: str):
    return serialization.load_der_public_key(b64decode(b64_str))


def importar_chave_priv(b64_str: str):
    return serialization.load_der_private_key(b64decode(b64_str), password=None)


def assinar(ecdsa_priv, mensagem: bytes):
    return b64encode(ecdsa_priv.sign(mensagem, ec.ECDSA(hashes.SHA256())))


def verificar_assinatura(ecdsa_pub, assinatura_b64, mensagem: bytes):
    assinatura = b64decode(assinatura_b64)
    try:
        ecdsa_pub.verify(assinatura, mensagem, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def cifrar_mensagem(mensagem: str, rsa_pub):
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, mensagem.encode(), None)
    tag = ciphertext[-16:]
    ciphertext = ciphertext[:-16]
    enc_key = rsa_pub.encrypt(key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    return {
        "ciphertext_b64": b64encode(ciphertext),
        "tag_autenticacao_b64": b64encode(tag),
        "nonce_b64": b64encode(nonce),
        "chave_sessao_cifrada_b64": b64encode(enc_key)
    }, key


def decifrar_mensagem(payload, rsa_priv):
    aes_key = rsa_priv.decrypt(b64decode(payload["chave_sessao_cifrada_b64"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes = AESGCM(aes_key)
    ciphertext = b64decode(payload["ciphertext_b64"]) + b64decode(payload["tag_autenticacao_b64"])
    return aes.decrypt(b64decode(payload["nonce_b64"]), ciphertext, None).decode()
