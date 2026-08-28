# Talao contact proof issuer

Application Flask dédiée à deux Verifiable Credentials :

- **Proof of Email** : vérification par code envoyé par e-mail ;
- **Proof of Phone** : vérification par code envoyé par SMS.

Les deux parcours délèguent l'émission OIDC4VCI à
[openid4vc-hub](https://openid4vc-hub.com). Le code de vérification est saisi
uniquement dans le wallet. Une émission n'est ajoutée au compteur local que
lorsque le hub retourne le statut `completed`.

## Architecture

```text
main.py
├── routes/emailpass_openid4vc_hub.py
├── routes/phonepass_openid4vc_hub.py
├── routes/hub_flow.py          # statut, SSE et déclenchement du compteur
├── routes/counter.py           # stockage atomique et anti-doublon
└── components/
    ├── openid4vc_hub.py        # client HTTP du hub
    ├── message.py              # envoi du code par e-mail
    └── sms.py                  # envoi du code par SMS
```

L'application utilise les sessions signées de Flask. Redis, DIDKit, Yoti, les
anciens drafts OIDC4VCI et les templates locaux de credentials ne font plus
partie du runtime.

## Installation

Prérequis : Python 3.10 ou plus récent.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Pour développer et exécuter les tests :

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Configuration

Les variables d'environnement sont prioritaires. Pour assurer la compatibilité
avec le déploiement historique, les secrets peuvent aussi rester dans les
fichiers locaux ignorés `keys.json` et `passwords.json`.

Variables indispensables :

| Variable | Repli historique | Usage |
|---|---|---|
| `ISSUER_SECRET_KEY` | `passwords.json["password"]` | signature des sessions Flask |
| `OPENID4VC_HUB_API_KEY` | `keys.json["openid4vc_hub_api_key"]` | authentification auprès du hub |
| `SMTP_PASSWORD` | `passwords.json["smtp_password"]` | envoi des codes e-mail |
| `SMS_API_TOKEN` | `passwords.json["sms_token"]` | envoi des codes SMS |

Configuration du hub :

| Variable | Valeur par défaut |
|---|---|
| `OPENID4VC_HUB_URL` | `https://openid4vc-hub.com` |
| `EMAIL_HUB_ISSUER` | `core-email-proof-issuer` |
| `EMAIL_CREDENTIAL_CONFIGURATION_ID` | `email_proof_sd_jwt` |
| `EMAIL_CREDENTIAL_CLAIM` | `email` |
| `PHONE_HUB_ISSUER` | `core-phone-proof-issuer` |
| `PHONE_CREDENTIAL_CONFIGURATION_ID` | `phone_sd_jwt` |
| `PHONE_CREDENTIAL_CLAIM` | `phone_number` |

Les deux issuers utilisent la même `OPENID4VC_HUB_API_KEY`. Les valeurs
téléphone correspondent au tenant hub de production et peuvent être remplacées
par variables d'environnement sans modifier le code.

Autres variables utiles :

- `MYENV=local|aws` (`local` par défaut) ;
- `ISSUER_HOST` et `ISSUER_PORT` (port local par défaut : `5100`) ;
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_FROM`, `SMTP_STARTTLS` ;
- `COUNTER_PATH` (par défaut : `counter.json`) ;
- `COUNTER_API_KEY` pour autoriser l'ancien endpoint `POST /counter/update` ;
- `COUNTER_SLACK_URL`, avec repli sur `passwords.json["slack_url"]` ;
- `ISSUANCE_EXPIRES_IN`, `HUB_REQUEST_TIMEOUT` et `EVENT_POLL_INTERVAL`.

## Compteur

Copier le fichier d'exemple uniquement lors d'une nouvelle installation :

```bash
cp counter.example.json counter.json
```

Ne jamais écraser un `counter.json` existant : il contient l'historique. Le
stockage conserve les anciennes clés éventuelles, mais `GET /counter/get`
n'expose que `total`, `emailpass` et `phonepass`.

Chaque émission hub est enregistrée avec son `issuance_id` dans une section
privée du même fichier. Cette écriture atomique rend le comptage idempotent,
même si le navigateur reconnecte le flux SSE ou si plusieurs workers voient le
statut final.

`POST /counter/update` est conservé pour compatibilité, limité aux deux types
actifs et protégé par l'en-tête `X-API-Key` correspondant à `COUNTER_API_KEY`.
Les nouveaux parcours ne l'utilisent pas : ils appellent directement le
compteur après confirmation du hub.

## Lancement

Développement :

```bash
MYENV=local python main.py
```

Production :

```bash
gunicorn -c gunicornconf.py wsgi:app
```

Les workers `gthread` permettent de maintenir les flux SSE. Le serveur envoie
aussi un commentaire keep-alive toutes les 15 secondes quand le statut ne
change pas.

## Routes

- `/` : sélection du type de preuve ;
- `/emailpass-hub` : Proof of Email ;
- `/phoneproof` : Proof of Phone ;
- `/counter/get` : compteurs publics ;
- `/healthz` : sonde de vie.

Les anciennes entrées `/emailproof`, `/emailpass`, `/emailproof-hub`,
`/phonepass-hub`, `/phonepass` et `/phoneproof-hub` restent disponibles comme
alias des deux parcours hub.

## Validation

```bash
python -m pytest -q
env PYTHONPYCACHEPREFIX=/tmp/issuer-pycache python -m py_compile \
  main.py wsgi.py environment.py gunicornconf.py components/*.py \
  routes/counter.py routes/hub_flow.py routes/emailpass_openid4vc_hub.py \
  routes/phonepass_openid4vc_hub.py tests/*.py
git diff --check
```

Les tests remplacent le hub, SMTP et SMS par des fakes : ils n'envoient aucun
message et n'appellent aucun service externe.
