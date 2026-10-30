from sqlalchemy.orm import Session
from sqlalchemy.sql import select

from app.models import OAuthClient, Scopes, PasswordPolicy, GrantType
from app.schemas import ClientCreate, ClientResponse, UpdatedResponse, ClientUpdate
from app.handlers.errors import ClientNotFound, ScopeNotFound, ClientError
from app.services.security.crypt import generate_secret

from app.services.resources import user_stores

def get_all_clients(db: Session):

    clients = db.execute(select(OAuthClient)).scalars().all()
    if not clients:
        return {"clients": []}

    payload = dict(

        clients=list(

            ClientResponse(

                client_id=x.client_id,
                client_secret=None,
                name=x.name,
                redirect_uri=x.redirect_uri,
                scopes=x.allowed_scopes,
                response_type=x.response_type,
                client_type=x.client_type,
                token_exp=x.token_exp,
                code_exp=x.code_exp,
                refresh_token_exp=x.refresh_token_exp

            ).model_dump(exclude_none=True)
            for x in clients)
    )

    return payload

def create_client(db: Session, data: ClientCreate):

    exists = db.execute(select(OAuthClient).filter_by(name=data.name)).scalar_one_or_none()

    if exists:
        raise ClientError("Client name already exists")

    client_id = generate_secret(24)

    client = OAuthClient(
        name=data.name,
        client_id=client_id,
        redirect_uri=str(data.redirect_uri),
        response_type=data.response_type,
        client_type=data.client_type,
        token_exp=data.token_exp,
        refresh_token_exp=data.refresh_token_exp,
        code_exp=data.code_exp
    )

    if data.user_store:

        user_store = user_stores.get_user_store(db, user_store_name=data.user_store, return_none=False)
        client.user_store = user_store

    for x in data.grant_types:

        grant = db.execute(select(GrantType).filter_by(name=x)).scalar_one_or_none()

        if grant is None:
            raise ClientError("Invalid grant type")

        client.grant_types.append(grant)

    for x in data.scopes:

        scope = db.execute(select(Scopes).filter_by(scope_name=x)).scalar_one_or_none()

        if scope is None:
            raise ScopeNotFound()

        client.scopes.append(scope)

    db.add(client)

    if data.password_policy:

        policy = PasswordPolicy(
            client_id=client_id,
            min_length=data.password_policy.min_length,
            max_length=data.password_policy.max_length,
            require_uppercase=data.password_policy.require_uppercase,
            require_lowercase=data.password_policy.require_lowercase,
            require_digits=data.password_policy.require_digits,
            require_special=data.password_policy.require_special
        )
        db.add(policy)


    # Public clients can have a secret, even they don't use?
    secret = client.generate_secret()

    db.commit()

    return ClientResponse(
        name=client.name,
        client_id=client_id,
        client_secret=secret,
        redirect_uri=client.redirect_uri,
        scopes=client.allowed_scopes,
        token_exp=client.token_exp,
        refresh_token_exp=client.refresh_token_exp,
        code_exp=client.code_exp,
        client_type=client.client_type,
        response_type=client.response_type,
        user_store=client.user_store.name if client.user_store else None
    ).model_dump(exclude_none=True)

def erase_client(db: Session, client_id: str):

    client = db.execute(select(OAuthClient).filter_by(client_id=client_id)).scalar_one_or_none()

    if not client:
        raise ClientNotFound()

    db.delete(client)
    db.commit()


def get_client(db: Session, client_name=None, client_id=None, return_none=False) -> OAuthClient | None:
    
    client_filters = []

    if client_name is not None:

        client_filters.append(OAuthClient.name == client_name)

    if client_id is not None:

        client_filters.append(OAuthClient.client_id == client_id)
    
    client = db.execute(select(OAuthClient).where(*client_filters)).scalar_one_or_none()

    if not client:

        if return_none:
            return None

        raise ClientNotFound()

    return client


def modify_client(db: Session, client_id: str, data: ClientUpdate):

    payload = data.model_dump(exclude_none=True, exclude_unset=True)

    client = get_client(db, client_id=client_id)

    if data.user_store:

        user_store = user_stores.get_user_store(db, user_store_name=data.user_store, return_none=False)
        payload["user_store"] = user_store

    if data.grant_types:
        payload["grant_types"] = []

        for x in data.grant_types:

            grant = db.execute(select(GrantType).filter_by(name=x)).scalar_one_or_none()

            if grant is None:
                raise ClientError("Invalid grant type")

            payload["grant_types"].append(grant)

    if data.scopes:
        payload["scopes"] = []

        for x in data.scopes:

            scope = db.execute(select(Scopes).filter_by(scope_name=x)).scalar_one_or_none()

            if scope is None:
                raise ScopeNotFound()

            payload["scopes"].append(scope)

    client.update_record(payload)

    client.save(db)