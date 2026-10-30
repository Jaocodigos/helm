from sqlalchemy.orm import Mapped, mapped_column, Session
from datetime import datetime
from uuid_utils import uuid7


class Default:

    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid7()))

    created_at: Mapped[datetime] = mapped_column(
        nullable=False,
        default=datetime.utcnow
    )

    updated_at: Mapped[datetime] = mapped_column(
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    def update_record(self, data: dict) -> None:
        for k in data:
            if data[k] is None:
                continue
            if hasattr(self, k):
                setattr(self, k, data[k])


    def save(self, session: Session):
        try:
            session.add(self)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e

    def delete(self, session: Session):
        try:
            session.delete(self)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e