from typing import Optional

from sqlalchemy.orm import Session

from .crud_models import UserCreate
from .db import DBContext
from .db_models import User
from .security import hash_password, manager


@manager.user_loader
def get_user(phone_num: str, db: Session = None) -> Optional[User]:
    """ Return the user with the corresponding email """
    if db is None:
        # No db session was provided so we have to manually create a new one
        # Closing of the connection is handled inside of DBContext.__exit__
        with DBContext() as db:
            return db.query(User).filter(User.phone == phone_num).first()
    else:
        return db.query(User).filter(User.phone == phone_num).first()


def check_user(phone: str, email: str = None, username: str = None, db: Session = None):
    """ Detect existing users with the same email, phone, or username. """
    duplicate = False
    message = ""
    if db is None:
        # No db session was provided so we have to manually create a new one
        # Closing of the connection is handled inside of DBContext.__exit__
        db = DBContext().db
    if db.query(User).filter(User.phone == phone).first() is not None:
        duplicate = True
        message = duplicate_message(message, "phone")
    if email is not None:
        if db.query(User).filter(User.email == email).first() is not None:
            duplicate = True
            message = duplicate_message(message, "email")
    if username is not None:
        if db.query(User).filter(User.username == username).first() is not None:
            duplicate = True
            message = duplicate_message(message, "username")
    return (duplicate, message)


def duplicate_message(message, field):
    if message == "":
        message = "We have another user with the same: {}".format(field)
    else:
        message += ", {}".format(field)
    return message


def create_user(db: Session, user: UserCreate) -> User:
    """ Create a new entry in the database user table """
    user_data = user.dict()
    if user_data["password"] is not None:
        user_data["password"] = hash_password(user.password)
    db_user = User(**user_data)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
