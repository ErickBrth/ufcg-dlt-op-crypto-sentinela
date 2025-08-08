import json
from .config import CONFIG
from .utils import load_json
from .crypto_engine import importar_chave_priv, importar_chave_pub, assinar, cifrar_mensagem
from .mqtt_client import MQTTClient

def enviar_mensagem(destinatario_id: str, mensagem: str):
    print(f"Enviando mensagem para {destinatario_id}...")

    minhas_chaves = load_json(CONFIG["chaves_local"])
    confiaveis = load_json(CONFIG["chaves_confiaveis"])

    if destinatario_id not in confiaveis:
        print("Destinatário não confiável.")
        return

    rsa_pub_destinatario = importar_chave_pub(confiaveis[destinatario_id]["rsa_publica"])
    ecdsa_priv = importar_chave_priv(minhas_chaves["ecdsa_privada"])

    payload, _ = cifrar_mensagem(mensagem, rsa_pub_destinatario)

    # Assinar (payload_hash = ciphertext + tag)
    hash_assinatura = payload["ciphertext_b64"] + payload["tag_autenticacao_b64"]
    payload["assinatura_b64"] = assinar(ecdsa_priv, hash_assinatura.encode())

    # Incluir remetente
    payload["remetente"] = CONFIG["id_unidade"]

    # Publicar
    mqtt = MQTTClient(CONFIG, lambda c, u, m: None)
    mqtt.publish(CONFIG["topicos"]["mensagem"] + destinatario_id, json.dumps(payload))
    print("Mensagem enviada.")

if __name__ == "__main__":
    # Exemplo de envio
    enviar_mensagem("UT-Echo", "Mensagem confidencial e autenticada de UT-Bravo.")
