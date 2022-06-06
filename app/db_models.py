from sqlalchemy import Boolean, Integer, Column, String

from db import Base


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True)
    role = Column(Integer)
    email = Column(String, unique=True, index=True)
    firstname = Column(String)
    lastname = Column(String)
    avatar = Column(String)
    telegram_id = Column(String)
    telegram_username = Column(String)
    telegram_chat_id = Column(String)
    username = Column(String)
    password = Column(String)