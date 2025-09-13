from sqlalchemy import Column,Integer,String,ForeignKey,create_engine
from sqlalchemy.orm import declarative_base,sessionmaker

engine =  create_engine("sqlite:///authorization.db")

Base = declarative_base()

SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    Username = Column(String, nullable=False)
    Email = Column(String, nullable =  False,unique=True)
    Password_user=Column(String, nullable= False)
    
    
# Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
