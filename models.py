from sqlalchemy import Boolean, Column, Integer, String


from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_name=Column(String,unique=True)
    email = Column(String, unique=True, index=True)
    expiry_date = Column(String)
    api_key = Column(String)




