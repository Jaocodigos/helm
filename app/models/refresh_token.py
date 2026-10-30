from datetime import datetime, UTC
from sqlalchemy import String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base
from app.models.default import Default

class RefreshToken(Default, Base):
    __tablename__ = "refresh_tokens"


    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    sub: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )



    client_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("clients.client_id"),
        index=True,
        nullable=False
    )

    issued_at: Mapped[datetime] = mapped_column(nullable=False)

    expires_at: Mapped[datetime] = mapped_column(nullable=False)

    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    replaced_by: Mapped[str | None] = mapped_column(
        ForeignKey("refresh_tokens.id"),
        nullable=True
    )


    def is_expired(self) -> bool:
        return self.expires_at.timestamp() < datetime.now(UTC).timestamp()

    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def revoke(self) -> None:
        self.expires_at = datetime.now(UTC)

    def rotate(self, new_refresh_token: str) -> None:
        self.revoke()
        self.replaced_by = new_refresh_token