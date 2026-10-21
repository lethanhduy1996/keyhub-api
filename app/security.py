import hashlib
import hmac
import secrets
import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from .config import get_settings

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def now_ts() -> int:
    return int(time.time())


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return password_hasher.verify(hashed, password)
    except (VerifyMismatchError, VerificationError):
        return False


def create_access_token(user_id: str) -> str:
    cfg = get_settings()
    now = now_ts()
    return jwt.encode(
        {'sub': user_id, 'typ': 'access', 'iss': 'independent-key-server',
         'aud': 'keyhub-ios', 'iat': now, 'exp': now + cfg.access_token_minutes * 60},
        cfg.jwt_secret, algorithm='HS256',
    )


def parse_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(
            token, get_settings().jwt_secret, algorithms=['HS256'],
            audience='keyhub-ios', issuer='independent-key-server',
            options={'require': ['sub', 'typ', 'exp', 'iat', 'iss', 'aud']},
        )
        return payload['sub'] if payload['typ'] == 'access' else None
    except (jwt.PyJWTError, KeyError, TypeError):
        return None


def secret_digest(value: str) -> str:
    return hmac.new(get_settings().key_pepper.encode(), value.encode(), hashlib.sha256).hexdigest()


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def new_license() -> tuple[str, str]:
    """Generate branded License Keys; database prefix stays a 12-char lookup ID."""
    prefix = secrets.token_hex(6).upper()
    secret = 'duyle-' + prefix + '-' + secrets.token_urlsafe(32)
    return prefix, secret


def license_prefix(raw: str) -> str | None:
    """Allow existing IKS licenses alongside newly issued duyle licenses."""
    parts = raw.strip().split('-', 2)
    if (len(parts) != 3 or parts[0] not in ('IKS', 'duyle')
            or len(parts[1]) != 12 or not parts[2]):
        return None
    if not all(ch in '0123456789abcdefABCDEF' for ch in parts[1]):
        return None
    return parts[1].upper()


def safe_digest_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def new_api_key() -> tuple[str, str]:
    prefix = secrets.token_hex(6).upper()
    return prefix, 'AKS-' + prefix + '-' + secrets.token_urlsafe(32)


def api_key_prefix(raw: str) -> str | None:
    parts = raw.strip().split('-', 2)
    if len(parts) != 3 or parts[0] != 'AKS' or len(parts[1]) != 12:
        return None
    return parts[1]
