from dataclasses import dataclass
from functools import cached_property
from uuid import uuid4

from nicegui import ui
from sqlalchemy import String, ForeignKey, select
from sqlalchemy.orm import mapped_column, relationship

from loguru import logger as log

import mileslib_infra
from mileslib_infra import Base


@dataclass
class Users(Base):
    __tablename__ = "users"
    __allow_unmapped__ = True

    uuid: str = mapped_column(primary_key=True)
    username: str = mapped_column(String, unique=True, nullable=False)
    email: str = mapped_column(String, unique=True, nullable=False)
    password: str = mapped_column(String, nullable=False)  # can be placeholder if using AAD
    access_level: str = mapped_column(String)
    phone: str = mapped_column(String, nullable=True)
    firstname: str = mapped_column(String)
    lastname: str = mapped_column(String)
    title: str = mapped_column(String)

    # Relationship to sessions
    sessions: list["Sessions"] = relationship("Sessions", back_populates="user")


@dataclass
class Sessions(Base):
    __tablename__ = "sessions"
    __allow_unmapped__ = True

    id: str = mapped_column(primary_key=True)  # ui.context.session.id
    user_uuid: str = mapped_column(ForeignKey("users.uuid"))
    access_token: str = mapped_column(String)
    expires_at: str = mapped_column(String)

    # Relationship back to user
    user: Users = relationship("Users", back_populates="sessions")


class Client:
    GLOBAL = mileslib_infra.Global()
    PROJECT = GLOBAL.projects["project"]
    clients = {}

    def __init__(self, client_id):
        self.client_id = client_id
        self.db = self.PROJECT.sqlite_orm.session

    @classmethod
    def get(cls, client_id):
        if client_id not in cls.clients:
            cls.clients[client_id] = cls(client_id)
        return cls.clients[client_id]

    @cached_property
    def session(self) -> Sessions | None:
        with self.db() as session:
            return session.get(Sessions, self.client_id)

    @cached_property
    def user(self) -> Users:
        _user = self.session.user if self.session else None
        if _user is None: raise PermissionError
        return _user

    def set_cookie(self, uuid: str):
        if not uuid:
            raise RuntimeError("Invalid UUID for cookie")
        ui.context.client.cookies['client_id'] = uuid

    def get_cookie(self, uuid: str) -> str | None:
        cookie = ui.context.client.cookies.get('client_id')
        if cookie != self.uuid: raise PermissionError
        return cookie

    def login(self, email, password) -> str:
        if not email.endswith('@phazebreak.com'):
            raise PermissionError

        with self.db() as session:
            stmt = select(Users).where(Users.email == email)
            user = session.execute(stmt).scalar_one_or_none()

            if not user:
                return self.signup(email, password)

            if user.password != password:
                raise PermissionError

            self.set_cookie(user.uuid)
            return user.uuid

    def signup(self, email: str, password: str) -> str:
        user = Users(
            uuid=str(uuid4()),
            email=email,
            username=email.split("@")[0],
            password=password,
            access_level="user",
            firstname="",
            lastname="",
            phone="",
            title=""
        )
        session_obj = Sessions(
            id=self.client_id,
            user_uuid=user.uuid,
            access_token="mock-token",
            expires_at="never"
        )

        self.set_cookie(user.uuid)
        return user.uuid

