
from sqlalchemy.sql import select
from datetime import datetime, timedelta, UTC
from jose import jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.services.security.crypt import PRIVATE_KEY, PUBLIC_KEY, generate_secret, hash_content
from app.schemas.token import TokenResponse, TokenRequest, IntrospectResponse
from app.models.refresh_token import RefreshToken
from app.models.token import Token
from app.handlers.errors.default import OauthError, UnauthorizedError


def get_token(db: Session, token: str, return_none: bool = False) -> Token | None:
    existent_token = db.execute(select(Token).filter_by(jti=token)).scalar_one_or_none()

    if not existent_token:

        if return_none:
            return None

        raise OauthError("invalid_token")

    return existent_token


def get_refresh_token(db: Session, refresh_token: str, return_none: bool = False) -> RefreshToken | None:

    refresh_token_id = refresh_token.split(".")[0]

    existent_refresh_token = db.execute(
        select(RefreshToken).filter_by(token_hash=refresh_token_id)).scalar_one_or_none()

    if not existent_refresh_token:

        if return_none:
            return None

        raise OauthError("invalid_token")

    return existent_refresh_token

def search_token(db: Session, data: TokenRequest, return_none: bool = False) -> Token | RefreshToken| None:

    if data.token_type_hint and data.token_type_hint == "access_token":
        token = get_token(db, data.token, True)

    elif data.token_type_hint and data.token_type_hint == "refresh_token":
        token = get_refresh_token(db, data.token, True)

    else:

        # If no token type hint is provided, we had to check both types.
        token = get_token(db, data.token, True)
        if not token:
            token = get_refresh_token(db, data.token, True)

    if not token:

        if return_none:
            return None

        else:
            raise OauthError("invalid_token")

    return token


def issue_token(db: Session, subject: str, scopes: list[str], client_exp: int, refresh_token=None) -> TokenResponse:

    issued_at = datetime.now(UTC)
    expire = issued_at + timedelta(
        minutes=client_exp
    )

    jti = generate_secret(32)

    store_token = Token(
        jti=jti,
        sub=subject,
        scopes="".join(scopes),
        issued_at=issued_at,
        expires_at=expire
    )

    store_token.save(db)

    payload = {
        "sub": subject,
        "iss": settings.ISSUER,
        "aud": settings.ISSUER,
        "scopes": scopes,
        "exp": expire,
        "jti": jti
    }

    token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


    return TokenResponse(
        access_token=token,
        expires_in=int(expire.timestamp()),
        token_type="bearer",
        refresh_token=refresh_token
    )

def validate_access_token(token: str, required_scopes: list) -> bool :

    try:
        is_valid = jwt.decode(token, PUBLIC_KEY, algorithms=settings.JWT_ALGORITHM)

    except Exception as e:
        raise UnauthorizedError("Invalid access token.")

    if is_valid["exp"] < datetime.now(UTC):
        raise UnauthorizedError("Invalid access token.")

    if is_valid["iss"] != settings.ISSUER:
        raise UnauthorizedError("Invalid issuer.")

    # In this case, the authorization server is a resource server too.
    if is_valid["aud"] != settings.ISSUER:
        raise UnauthorizedError("Invalid audience.")

    if not all(x in is_valid["scopes"] for x in required_scopes):
        raise UnauthorizedError("Invalid scopes for this operation.")

    return True


def issue_refresh_token(db: Session, user_id: str, client_id: str, refresh_token_exp: int) -> tuple[str, str]:

    issued_at = datetime.now(UTC)
    expire = issued_at + timedelta(
        minutes=refresh_token_exp
    )

    token = generate_secret(64)

    refresh_token = RefreshToken(
        token_hash=hash_content(token),
        user_id=user_id,
        client_id=client_id,
        issued_at=issued_at,
        expires_at=expire
    )

    db.add(refresh_token)
    db.commit()

    token = f"{refresh_token.id}.{token}"

    return token, refresh_token.id

def validate_and_issue_refresh_token(db: Session, refresh_token: str, refresh_token_exp: int) -> tuple[str, str]:

    refresh_token = get_refresh_token(db, refresh_token, return_none=True)

    if not refresh_token:
        raise OauthError("invalid_grant")

    if refresh_token.is_expired() or refresh_token.is_revoked():
        raise OauthError("invalid_grant")


    token, token_id = issue_refresh_token(
        db=db,
        user_id=refresh_token.user_id,
        client_id=refresh_token.client_id,
        refresh_token_exp=refresh_token_exp
    )

    refresh_token.rotate(token_id)

    db.commit()

    return token, refresh_token.user_id



"""
    As described in Revoke RFC 7009, an invalid token can't trigger a error response. We just ignore it and return 200 in the endpoint. 
"""
def revoke_token(db: Session, data: TokenRequest):

    token = search_token(db, data, return_none=True)

    if token:
        token.revoke()


def introspect_token(db: Session, data: TokenRequest):

    token = search_token(db, data, return_none=True)

    if token.is_expired():
        return IntrospectResponse(
            active=False
        )

    return IntrospectResponse(
        active=True,
        client_id=token.client_id,
        sub=token.sub,
        exp=token.expires_at
    )

