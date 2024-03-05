from datetime import datetime
from sqlalchemy import Column, Date,Integer,String,DateTime,Boolean,ForeignKey,JSON 
from .database import Base
from sqlalchemy.orm import relationship

class Otp(Base):
    __tablename__="otp"
    id=Column(Integer,primary_key=True,index=True)
    user_id=Column(String)
    password=Column(String)
    otp=Column(Integer)
    description =Column(String)

class User(Base):
    __tablename__="user"
    id=Column(Integer,primary_key=True,index=True)
    phone=Column(String)
    email=Column(String)
    password=Column(String)
    created_on=Column(DateTime,default=datetime.now())
    updated_on = Column(DateTime,default=datetime.now())
    profile = relationship("Profile",back_populates="user")
    
class Profile(Base):
    __tablename__="profile"
    id=Column(Integer,primary_key=True,index=True)
    firstname=Column(String)
    lastname=Column(String)
    dob=Column(Date)
    age=Column(Integer)
    address=Column(String)
    profile_pic=Column(String)
    user_id=Column(Integer,ForeignKey("user.id"))
    user = relationship("User",back_populates="profile")
    
        
class SendRequest(Base):
    __tablename__="send_request"
    id= Column(Integer,primary_key=True,index=True)
    sender_id =Column(Integer)
    receiver_id =Column(Integer)
    status=Column(Boolean,default=False)
    created_on=Column(DateTime,default=datetime.now())
    updated_on = Column(DateTime,default=datetime.now())
    
class FriendList(Base):
    __tablename__="friendlist"
    id=Column(Integer,primary_key=True,index=True)
    user_id =Column(Integer)
    friends =Column(JSON)
    blocked_list = Column(JSON)
    
class Room(Base):
    __tablename__="user_room"
    id =Column(Integer,primary_key=True,index=True)
    room_id =Column(Integer)
    sender_id=Column(Integer)
    receiver_id= Column(Integer)

class Conversation(Base):
    __tablename__="user_conversation"
    id=Column(Integer,primary_key=True,index=True)
    room_id =Column(Integer)
    msg=Column(String,default="hello")
    status =Column(String,default ="Unread")
       
        

    
