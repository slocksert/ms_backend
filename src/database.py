from sqlmodel import SQLModel, create_engine, Session

from decouple import config

engine = create_engine(config('DB_URL')) 

#create and delete database used in alembic migrations
def create_database() -> None:
    SQLModel.metadata.create_all(engine, checkfirst=True) 

def delete_database() -> None:
    SQLModel.metadata.drop_all(engine, checkfirst=True)

def get_session():
    with Session(engine) as session:
        yield session
