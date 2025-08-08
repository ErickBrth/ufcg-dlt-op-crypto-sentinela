import json
import base64
from .utils import load_json
from .crypto_engine import importar_chave_pub, importar_chave_priv, verificar_assinatura, decifrar_mensagem
from .config import CONFIG
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def handle_message(client, userdata, msg):
    print(f"\n[INFO] Mensagem recebida de {msg.topic}")
    try:
        data = json.loads(msg.payload.decode())

        # Revogação
        if "revogacao" in data:
            remetente = data["remetente"]
            assinatura = base64.b64decode(data["assinatura_b64"])
            rev_data = data["revogacao"]

            json_rev = json.dumps(rev_data, separators=(',', ':')).encode()
            trusted = load_json(CONFIG["chaves_confiaveis"])

            if remetente not in trusted:
                print(f"[WARN] Remetente '{remetente}' não está na lista confiável.")
                return

            pub_ecdsa = importar_chave_pub(trusted[remetente]["chave_publica_ecdsa"])

            verificar_assinatura(pub_ecdsa, assinatura, json_rev)

            unidade_revogada = rev_data["unidade_revogada"]
            if unidade_revogada in trusted:
                del trusted[unidade_revogada]
                with open(CONFIG["chaves_confiaveis"], "w") as f:
                    json.dump(trusted, f, indent=2)
                print(f"[INFO] Unidade '{unidade_revogada}' foi revogada com sucesso.")
            else:
                print(f"[INFO] Unidade '{unidade_revogada}' já não está entre os confiáveis.")
            return

        # Mensagem criptografada comum
        remetente = data["remetente"]
        trusted = load_json(CONFIG["chaves_confiaveis"])
        
        


        if remetente not in trusted:
            print("[WARN] Remetente desconhecido.")
            return

        pub_ecdsa = importar_chave_pub(trusted[remetente]["chave_publica_ecdsa"])

        # Recriar conteúdo assinado: hash SHA256 da mensagem original
        ciphertext = base64.b64decode(data["ciphertext_b64"])
        tag = base64.b64decode(data["tag_autenticacao_b64"])
        assinatura_b64 = data["assinatura_b64"]
        assinatura = base64.b64decode(assinatura_b64)

        # Para consistência com o projeto: hash da mensagem original
        nonce = base64.b64decode(data["nonce_b64"])
        chave_sessao_cifrada = base64.b64decode(data["chave_sessao_cifrada_b64"])

        # Decifra com chave RSA privada local
        minhas_chaves = load_json(CONFIG["chaves_local"])
        rsa_priv = importar_chave_priv(minhas_chaves["rsa_privada"])

        msg_clara = decifrar_mensagem(data, rsa_priv)

        if verificar_assinatura(pub_ecdsa, assinatura, msg_clara.encode()):
            print("Mensagem recebida com sucesso e verificada:")
            print(f"> {msg_clara}")
        else:
            print("[WARN] Assinatura inválida. A mensagem foi alterada ou forjada.")


    except Exception as e:
        print(f"[ERROR] Falha ao processar mensagem: {e}")

