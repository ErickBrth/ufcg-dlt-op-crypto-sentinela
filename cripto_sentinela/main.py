import json
from .config import CONFIG
from .mqtt_client import MQTTClient
from .crypto_engine import gerar_chaves, exportar_chave, cifrar_mensagem, assinar
from .utils import save_json, load_json
from .message_handler import handle_message

def publicar_chaves():
    chaves = gerar_chaves()
    data = {
        "rsa_publica": exportar_chave(chaves["rsa_pub"]),
        "rsa_privada": exportar_chave(chaves["rsa_priv"], True),
        "ecdsa_publica": exportar_chave(chaves["ecdsa_pub"]),
        "ecdsa_privada": exportar_chave(chaves["ecdsa_priv"], True)
    }
    save_json(CONFIG["chaves_local"], data)

    payload = {
        "id_unidade": CONFIG["id_unidade"],
        "chave_publica_rsa": data["rsa_publica"],
        "chave_publica_ecdsa": data["ecdsa_publica"]
    }

    mqtt = MQTTClient(CONFIG, lambda c, u, m: None)
    mqtt.publish(CONFIG["topicos"]["chaves"] + CONFIG["id_unidade"], json.dumps(payload), retain=True)
    print("Chaves publicadas.")

def enviar_mensagem(destinatario, mensagem):
    confiaveis = load_json(CONFIG["chaves_confiaveis"])
    pub_rsa = importar_chave_pub(confiaveis[destinatario]["chave_publica_rsa"])
    pub_ecdsa = importar_chave_pub(load_json(CONFIG["chaves_local"])["ecdsa_privada"])
    payload_crypto, _ = cifrar_mensagem(mensagem, pub_rsa)
    assinatura = assinar(pub_ecdsa, (payload_crypto["ciphertext_b64"] + payload_crypto["tag_autenticacao_b64"]).encode())

    payload_crypto["assinatura_b64"] = assinatura
    payload_crypto["remetente"] = CONFIG["id_unidade"]

    mqtt = MQTTClient(CONFIG, lambda c, u, m: None)
    mqtt.publish(CONFIG["topicos"]["mensagem"] + destinatario, json.dumps(payload_crypto))
    print("Mensagem enviada para", destinatario)

if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

    publicar_chaves()
    print("Iniciando ouvinte MQTT...\n")

    mqtt = MQTTClient(CONFIG, handle_message)
    mqtt.subscribe(CONFIG["topicos"]["mensagem"] + CONFIG["id_unidade"])
    mqtt.subscribe(CONFIG["topicos"]["revogacao"])
    mqtt.start()

    try:
        input("Pressione ENTER para encerrar...\n")
    except KeyboardInterrupt:
        print("Encerrando...")
    finally:
        mqtt.stop()
