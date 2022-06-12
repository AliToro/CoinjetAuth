import os

from pydantic import BaseSettings

user = os.environ['coinjet_db_user']
password = os.environ['coinjet_db_password']
host = os.environ['coinjet_db_host']
db_name = os.environ['coinjet_db_dbname']


class Settings():
    secret: str  # autmatically taken from environement variable
    # database_uri: str = "sqlite:///../app.db"
    database_uri: str = "postgresql://{}:{}@{}/{}".format(user, password, host, db_name)
    token_url: str = "/auth/token"
    secret = os.environ['secret']


DEFAULT_SETTINGS = Settings()
