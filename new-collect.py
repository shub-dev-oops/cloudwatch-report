# app.py
import os, json, time, logging, urllib.parse, urllib.request
import boto3

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

SECRETS_ARN = os.environ["SECRET_ID"]
DDB_TABLE   = os.environ["DDB_TABLE"]

sm  = boto3.client("secretsmanager")
ddb = boto3.client("dynamodb")

# Cache secrets & token in-memory for this container
_secret_cache = None
_token_cache = {"value": None, "exp": 0}

def get_secret():
    global _secret_cache
    if _secret_cache:
        return _secret_cache
    s = sm.get_secret_value(SecretId=SECRETS_ARN)["SecretString"]
    _secret_cache = json.loads(s)
    return _secret_cache

def get_app_token():
    """Client-credentials token for Graph; cached for ~50 min."""
    if _token_cache["value"] and _token_cache["exp"] > time.time() + 60:
        return _token_cache["value"]
    sec = get_secret()
    form = url
