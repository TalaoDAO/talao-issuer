# Installation

La procédure d'installation et la configuration à jour sont décrites dans
[`README.md`](README.md#installation).

Résumé :

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
MYENV=local python main.py
```

Le lancement exige les secrets du hub, SMTP, SMS et de session décrits dans le
README. Redis et DIDKit ne sont plus nécessaires.
