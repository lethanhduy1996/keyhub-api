from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db, init_db
from .models import Activation, APICredential, LicenseKey, RefreshSession, User
from .schemas import (ActivationOut, APICredentialOut, APICredentialIssuedOut, CreateAPICredentialIn, IssueKeyIn, KeyActionIn, KeyIssuedOut,
                      KeyOut, LoginIn, MessageOut, RefreshIn, RegisterIn,
                      TokensOut, UserOut, VerifyOut)
from .security import (api_key_prefix, create_access_token, hash_password, license_prefix,
                       new_api_key, new_license, new_refresh_token, now_ts,
                       parse_access_token, safe_digest_equal, secret_digest,
                       verify_password)

settings = get_settings()
http_bearer = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # MVP only: introduce Alembic migrations before production upgrades.
    yield


app = FastAPI(title=settings.app_name, version='0.1.0', lifespan=lifespan)
if settings.allowed_origins:
    app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.allowed_origins.split(',')],
                       allow_credentials=False, allow_methods=['GET', 'POST', 'DELETE'], allow_headers=['Authorization', 'Content-Type'])


def unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail='Authentication required', headers={'WWW-Authenticate': 'Bearer'})


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(http_bearer), db: Session = Depends(get_db)) -> User:
    if creds is None or creds.scheme.lower() != 'bearer':
        raise unauthorized()
    user_id = parse_access_token(creds.credentials)
    user = db.get(User, user_id) if user_id else None
    if user is None or not user.is_active:
        raise unauthorized()
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, 'Admin access required')
    return user


def tokens_for(user: User, db: Session) -> TokensOut:
    raw = new_refresh_token()
    db.add(RefreshSession(user_id=user.id, token_digest=secret_digest(raw),
                          expires_at=now_ts() + settings.refresh_token_days * 86400))
    db.commit()
    return TokensOut(access_token=create_access_token(user.id), refresh_token=raw,
                     expires_in=settings.access_token_minutes * 60)


def key_out(key: LicenseKey, db: Session) -> KeyOut:
    device_count = db.scalar(select(func.count()).select_from(Activation).where(Activation.key_id == key.id)) or 0
    return KeyOut(id=key.id, prefix=key.prefix, owner_email=key.owner.email,
                  note=key.note, created_at=key.created_at, expires_at=key.expires_at,
                  revoked_at=key.revoked_at, device_limit=key.device_limit, device_count=device_count,
                  is_active=key.revoked_at is None and key.expires_at > now_ts())


def device_alias(device_hash: str) -> str:
    """Pseudonymous administrative identifier; not an Apple hardware UDID."""
    return f'KH-{device_hash[:8].upper()}-{device_hash[8:16].upper()}'


def key_for_secret(raw: str, db: Session, lock: bool = False) -> LicenseKey | None:
    prefix = license_prefix(raw)
    if prefix is None:
        return None
    stmt = select(LicenseKey).where(LicenseKey.prefix == prefix)
    if lock:
        stmt = stmt.with_for_update()
    key = db.scalar(stmt)
    if key is None or not safe_digest_equal(key.key_digest, secret_digest(raw)):
        return None
    return key


@app.get('/api/v1/health')
def health():
    return {'status': 'ok'}


@app.post('/api/v1/auth/register', response_model=UserOut, status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    email = str(data.email).lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, 'Email already registered')
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(409, 'Email already registered') from None
    db.refresh(user)
    return UserOut(id=user.id, email=user.email, is_admin=user.is_admin, created_at=user.created_at)


@app.post('/api/v1/auth/login', response_model=TokensOut)
def login(data: LoginIn, db: Session = Depends(get_db)):
    email = str(data.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, 'Invalid credentials')
    return tokens_for(user, db)


@app.post('/api/v1/auth/refresh', response_model=TokensOut)
def refresh(data: RefreshIn, db: Session = Depends(get_db)):
    # Serialize concurrent refresh attempts in PostgreSQL so that a refresh token is single-use.
    session = db.scalar(select(RefreshSession).where(
        RefreshSession.token_digest == secret_digest(data.refresh_token)).with_for_update())
    if session is None or session.revoked_at is not None or session.expires_at <= now_ts():
        raise unauthorized()
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise unauthorized()
    session.revoked_at = now_ts()
    return tokens_for(user, db)


@app.post('/api/v1/auth/logout', response_model=MessageOut)
def logout(data: RefreshIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    session = db.scalar(select(RefreshSession).where(
        RefreshSession.token_digest == secret_digest(data.refresh_token), RefreshSession.user_id == user.id))
    if session:
        session.revoked_at = now_ts()
        db.commit()
    return MessageOut(message='Signed out')


@app.get('/api/v1/me', response_model=UserOut)
def me(user: User = Depends(current_user)):
    return UserOut(id=user.id, email=user.email, is_admin=user.is_admin, created_at=user.created_at)


@app.get('/api/v1/keys', response_model=list[KeyOut])
def list_keys(limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0),
              user: User = Depends(current_user), db: Session = Depends(get_db)):
    stmt = select(LicenseKey).order_by(LicenseKey.created_at.desc(), LicenseKey.id.desc()).limit(limit).offset(offset)
    if not user.is_admin:
        stmt = stmt.where(LicenseKey.owner_id == user.id)
    return [key_out(key, db) for key in db.scalars(stmt).all()]


@app.post('/api/v1/keys', response_model=KeyIssuedOut, status_code=201)
def issue_key(data: IssueKeyIn, admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    owner = db.scalar(select(User).where(User.email == str(data.owner_email).lower(), User.is_active.is_(True)))
    if owner is None:
        raise HTTPException(404, 'Active user not found')
    prefix, secret = new_license()
    key = LicenseKey(owner_id=owner.id, prefix=prefix, key_digest=secret_digest(secret),
                     note=data.note, device_limit=data.device_limit,
                     expires_at=now_ts() + data.expires_days * 86400)
    db.add(key)
    db.commit()
    db.refresh(key)
    return KeyIssuedOut(**key_out(key, db).model_dump(), secret=secret)


@app.post('/api/v1/keys/activate', response_model=KeyOut)
def activate(data: KeyActionIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    key = key_for_secret(data.key, db, lock=True)
    if key is None or key.owner_id != user.id or key.revoked_at is not None or key.expires_at <= now_ts():
        raise HTTPException(400, 'License cannot be activated')
    digest = secret_digest(data.device_id)
    existing = db.scalar(select(Activation).where(Activation.key_id == key.id, Activation.device_hash == digest))
    if existing is None:
        count = db.scalar(select(func.count()).select_from(Activation).where(Activation.key_id == key.id)) or 0
        if count >= key.device_limit:
            raise HTTPException(409, 'Device limit reached')
        db.add(Activation(key_id=key.id, device_hash=digest, label=data.label))
        db.commit()
    return key_out(key, db)


@app.post('/api/v1/keys/activate-with-key', response_model=VerifyOut)
def activate_with_key(data: KeyActionIn, db: Session = Depends(get_db)):
    key = key_for_secret(data.key, db, lock=True)
    if key is None or key.revoked_at is not None or key.expires_at <= now_ts() or not key.owner.is_active:
        raise HTTPException(400, 'License invalid or expired')
    digest = secret_digest(data.device_id)
    existing = db.scalar(select(Activation.id).where(Activation.key_id == key.id, Activation.device_hash == digest))
    if existing is None:
        count = db.scalar(select(func.count()).select_from(Activation).where(Activation.key_id == key.id)) or 0
        if count >= key.device_limit:
            raise HTTPException(409, 'Device limit reached')
        db.add(Activation(key_id=key.id, device_hash=digest, label=data.label))
        db.commit()
    return VerifyOut(valid=True, device_code=device_alias(digest))


@app.post('/api/v1/keys/verify', response_model=VerifyOut)
def verify(data: KeyActionIn, db: Session = Depends(get_db)):
    # Intended for clients that know both license secret and enrolled device UUID.
    # Add rate limits and stronger device attestation before public production use.
    key = key_for_secret(data.key, db)
    if key is None or key.revoked_at is not None or key.expires_at <= now_ts():
        return VerifyOut(valid=False)
    existing = db.scalar(select(Activation.id).where(
        Activation.key_id == key.id, Activation.device_hash == secret_digest(data.device_id)))
    return VerifyOut(valid=existing is not None,
                     device_code=device_alias(secret_digest(data.device_id)) if existing is not None else None)


@app.get('/api/v1/keys/{key_id}/devices', response_model=list[ActivationOut])
def list_devices(key_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    key = db.get(LicenseKey, key_id)
    if key is None:
        raise HTTPException(404, 'License not found')
    if not user.is_admin and key.owner_id != user.id:
        raise HTTPException(403, 'No access to this license')
    return [ActivationOut(id=device.id, label=device.label, created_at=device.created_at,
                          device_code=device_alias(device.device_hash))
            for device in db.scalars(select(Activation).where(Activation.key_id == key.id)
                                     .order_by(Activation.created_at.desc())).all()]


@app.delete('/api/v1/keys/{key_id}/devices/{device_id}', response_model=MessageOut)
def delete_device(key_id: str, device_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    key = db.get(LicenseKey, key_id)
    if key is None:
        raise HTTPException(404, 'License not found')
    if not user.is_admin and key.owner_id != user.id:
        raise HTTPException(403, 'No access to this license')
    device = db.scalar(select(Activation).where(Activation.key_id == key.id, Activation.id == device_id))
    if device is None:
        raise HTTPException(404, 'Device not found')
    db.delete(device)
    db.commit()
    return MessageOut(message='Device removed')


@app.post('/api/v1/keys/{key_id}/revoke', response_model=KeyOut)
def revoke(key_id: str, admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    key = db.get(LicenseKey, key_id)
    if key is None:
        raise HTTPException(404, 'License not found')
    if key.revoked_at is None:
        key.revoked_at = now_ts()
        db.commit()
    return key_out(key, db)


# API credentials are separate from device-bound licenses. Their raw values are
# displayed once and are only accepted by the dedicated /api-keys/check endpoint.
@app.get('/api/v1/api-keys', response_model=list[APICredentialOut])
def list_api_keys(user: User = Depends(current_user), db: Session = Depends(get_db)):
    entries = db.scalars(select(APICredential).where(APICredential.owner_id == user.id)
                         .order_by(APICredential.created_at.desc()).limit(100)).all()
    return [APICredentialOut.model_validate({
        'id': item.id, 'prefix': item.prefix, 'label': item.label,
        'created_at': item.created_at, 'revoked_at': item.revoked_at,
    }) for item in entries]


@app.post('/api/v1/api-keys', response_model=APICredentialIssuedOut, status_code=201)
def create_api_key(data: CreateAPICredentialIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    prefix, raw = new_api_key()
    item = APICredential(owner_id=user.id, prefix=prefix, key_digest=secret_digest(raw), label=data.label)
    db.add(item)
    db.commit()
    db.refresh(item)
    return APICredentialIssuedOut(id=item.id, prefix=item.prefix, label=item.label,
                                  created_at=item.created_at, revoked_at=None, secret=raw)


@app.delete('/api/v1/api-keys/{key_id}', response_model=MessageOut)
def revoke_api_key(key_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = db.get(APICredential, key_id)
    if item is None or item.owner_id != user.id:
        raise HTTPException(404, 'API credential not found')
    if item.revoked_at is None:
        item.revoked_at = now_ts()
        db.commit()
    return MessageOut(message='API key revoked')


@app.get('/api/v1/api-keys/check', response_model=MessageOut)
def check_api_key(x_api_key: str | None = Header(default=None, max_length=200),
                  db: Session = Depends(get_db)):
    if not x_api_key:
        raise unauthorized()
    prefix = api_key_prefix(x_api_key)
    if prefix is None:
        raise unauthorized()
    item = db.scalar(select(APICredential).where(APICredential.prefix == prefix))
    if item is None or item.revoked_at is not None or not item.owner.is_active or not safe_digest_equal(
        item.key_digest, secret_digest(x_api_key)
    ):
        raise unauthorized()
    return MessageOut(message='API key is valid')
