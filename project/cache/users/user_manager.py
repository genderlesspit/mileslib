from dataclasses import dataclass

@dataclass
class User:
    uuid: str
    access_level: str
    username: str
    password: str
    session: str
    email: str
    phone: str
    firstname: str
    lastname: str
    title: str