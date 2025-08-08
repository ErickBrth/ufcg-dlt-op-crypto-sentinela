import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from mqtt_client import MQTTClient
from config import CONFIG


def revogar_unidade(unidade_id: str):
    timestamp = datetime.now(timezone.utc).isoformat()
    mensagem_revogacao = {
        "unidade_revogada": unidade_id,
        "timestamp": timestamp
    }

   
    json_bytes = json.dumps(mensagem_revogacao, separators=(',', ':')).encode()
    private_key_bytes = base64.b64decode(CONFIG["minhas_chaves"]["ecdsa_privada"])
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)

    assinatura = private_key.sign(
        json_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    assinatura_b64 = base64.b64encode(assinatura).decode()

    pacote = {
        "remetente": CONFIG["id_unidade"],
        "revogacao": mensagem_revogacao,
        "assinatura_b64": assinatura_b64
    }

    mqtt = MQTTClient(CONFIG, lambda c, u, m: None)
    mqtt.client.publish("sisdef/broadcast/revogacao", json.dumps(pacote), qos=1)
    print(f"[INFO] Revogação da unidade '{unidade_id}' publicada.")


if __name__ == "__main__":
    from sys import argv
    if len(argv) != 2:
        print("Uso: python -m cripto_sentinela.revogar_unidade <id_unidade>")
    else:
        revogar_unidade(argv[1].lower())
