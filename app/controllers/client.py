from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
from typing import Annotated

from app.db.session import get_db
from app.schemas.clients import ClientCreate, ClientUpdate
from app.schemas.default import DeletedResponse, UpdatedResponse
from app.services.security.auth import admin_authentication
from app.services.resources.client import get_all_clients, create_client, erase_client, modify_client

router = APIRouter(prefix="/api", tags=["Clients"])


@router.get("/clients")
def get_clients(
    db: Session = Depends(get_db),
    _: None = Depends(admin_authentication),
):

    clients = get_all_clients(db=db)

    return clients

@router.post("/clients")
def register_client(
    data: Annotated[ClientCreate, Body()],
    db: Session = Depends(get_db),
    _: None = Depends(admin_authentication),
):

    new_client = create_client(db=db, data=data)

    return new_client

@router.patch("/clients/{client_id}")
def update_client(
        client_id: str,
        data: Annotated[ClientUpdate, Body()],
        db: Session = Depends(get_db),
        _: None = Depends(admin_authentication)
):
    modify_client(db=db, client_id=client_id, data=data)

    return UpdatedResponse

@router.delete("/clients/{client_id}")
def delete_client(
        client_id: str,
        db: Session = Depends(get_db),
        _: None = Depends(admin_authentication),
):

    erase_client(db=db, client_id=client_id)

    return DeletedResponse