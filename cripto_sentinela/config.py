import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, "config.json"), encoding="utf-8") as f:
    CONFIG = json.load(f)

CONFIG["chaves_local"] = os.path.join(BASE_DIR, CONFIG["chaves_local"])
CONFIG["chaves_confiaveis"] = os.path.join(BASE_DIR, CONFIG["chaves_confiaveis"])
