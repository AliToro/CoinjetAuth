from typing import Optional
from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    phone: str
    role: Optional[int]
    email: Optional[EmailStr]
    firstname: Optional[str]
    lastname: Optional[str]
    avatar: Optional[str]  # FileUrl of pydantic is a better type option
    telegram_id: Optional[str]
    telegram_username: Optional[str]
    telegram_chat_id: Optional[str]
    username: Optional[str]
    password: Optional[str]


