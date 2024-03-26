from sqlmodel import SQLModel, create_engine

from decouple import config

engine = create_engine(config('DB_URL')) 

#create and delete database used in alembic migrations
def create_database():
    SQLModel.metadata.create_all(engine, checkfirst=True) 

def delete_database():
    SQLModel.metadata.drop_all(engine, checkfirst=True)