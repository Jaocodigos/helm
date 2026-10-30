from datetime import datetime, UTC
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base
from app.models.default import Default


class Token(Default, Base):
    __tablename__ = "access_tokens"

    jti: Mapped[str] = mapped_column(String(40), nullable=False, index=True)

    sub: Mapped[str] = mapped_column(String(100), nullable=False)

    scopes: Mapped[str] = mapped_column(String(100), nullable=False)

    issued_at: Mapped[datetime] = mapped_column(default=datetime.now(UTC))

    expires_at: Mapped[datetime] = mapped_column(nullable=False)


    def revoke(self) -> None:
        self.expires_at = datetime.now(UTC)