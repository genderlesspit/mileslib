from dataclasses import dataclass
from functools import cached_property
from typing import Optional
from uuid import uuid4

from sqlalchemy import String, select
from sqlalchemy.orm import mapped_column, Mapped

import mileslib_infra
from mileslib_infra import Base

from loguru import logger as log


@dataclass
class UserDefaults:
    authenticated: bool
    user: str | None


class Users(Base):
    __tablename__ = "users"

    uuid: Mapped[str] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    access_level: Mapped[str] = mapped_column(String)
    phone: Mapped[str] = mapped_column(String, nullable=True)
    firstname: Mapped[str] = mapped_column(String)
    lastname: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)

    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "username": self.username,
            "email": self.email,
            "access_level": self.access_level,
            "phone": self.phone,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "title": self.title
        }


@dataclass
class UserDTO:
    uuid: str
    username: str
    email: str
    access_level: str
    phone: Optional[str]
    firstname: str
    lastname: str
    title: str

    @classmethod
    def from_orm(cls, user: Users) -> "UserDTO":
        return cls(**user.to_dict())


class Client:
    GLOBAL = mileslib_infra.Global()
    PROJECT = GLOBAL.projects["project"]
    clients = {}

    def __init__(self, client_session_uuid: str, email, password):
        self.client_session_uuid = client_session_uuid
        self.email = email
        self.password = password
        log.debug(f"[Client] Attempting to initialize client at {self.client_session_uuid} with {self.email}")
        self.db = self.PROJECT.sqlite_orm.session
        log.debug(f"[Client] Attempting to retrieve user information from {self.PROJECT.sqlite.path}")
        _ = self.user
        log.debug(f"[Client] Retrieved user information: {self.user}")
        self.client_metadata = UserDefaults(authenticated=True, user=self.user["uuid"])

    @classmethod
    def get(cls, client_session_uuid: str):
        if client_session_uuid not in cls.clients: raise PermissionError
        return cls.clients[client_session_uuid]

    @classmethod
    def new(cls, client_session_uuid: str, email, password):
        if client_session_uuid in cls.clients: return cls.clients[client_session_uuid]
        cls.clients[client_session_uuid] = cls(client_session_uuid, email, password)
        return cls.clients[client_session_uuid]

    @cached_property
    def user(self) -> dict:
        if not self.email.endswith('@phazebreak.com'):
            raise PermissionError

        with self.db() as session:
            stmt = select(Users).where(Users.email == self.email)
            user = session.execute(stmt).scalar_one_or_none()
            if not user:
                return self.signup()
            if user.password != self.password:
                raise PermissionError
            session.refresh(user)

            user = UserDTO.from_orm(user)
            return user.__dict__

    def signup(self) -> dict:
        user = Users(
            uuid=str(uuid4()),
            email=self.email,
            username=self.email.split("@")[0],
            password=self.password,
            access_level="user",
            firstname="",
            lastname="",
            phone="",
            title=""
        )
        with self.db() as session:
            session.add(user)
            session.commit()
            session.refresh(user)

        user = UserDTO.from_orm(user)
        return user.__dict__
