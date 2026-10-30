from pydantic import BaseModel
from typing import Optional, Literal, Union

class AuthorizationCodeGrant(BaseModel):

    grant_type: Literal["authorization_code"]
    code: str
    client_id: str
    redirect_uri: str
    code_verifier: str

class RefreshTokenGrant(BaseModel):

    grant_type: Literal["refresh_token"]
    refresh_token: str
    client_id: str


TokenExchange = Union[AuthorizationCodeGrant, RefreshTokenGrant]

class TokenResponse(BaseModel):
    access_token: str
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = None

    model_config = {
        "exclude_none": True
    }


class TokenRequest(BaseModel):
    token: str
    token_type_hint: Optional[str] = None

    def validate_token_type_hint(self, value: str):
        if value not in ["access_token", "refresh_token"]:
            raise ValueError("invalid token_type_hint")
        return value

class IntrospectResponse(BaseModel):
    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    sub: Optional[str] = None
    exp: Optional[int] = None