from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


url = get_settings().database_url
kwargs = {'check_same_thread': False} if url.startswith('sqlite:') else {}
engine = create_engine(url, pool_pre_ping=True, connect_args=kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    with SessionLocal() as session:
        yield session


def init_db():
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
