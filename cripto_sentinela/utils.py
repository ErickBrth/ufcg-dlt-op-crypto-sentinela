import base64
import json

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64decode(data: str) -> bytes:
    return base64.b64decode(data)

def save_json(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)
