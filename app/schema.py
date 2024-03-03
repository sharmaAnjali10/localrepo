from datetime import date
from pydantic import BaseModel,EmailStr,Field
from typing import Optional

class OtpSchema(BaseModel):
    email:Optional[EmailStr]=None
    phone:Optional[str]=None
    password:Optional[str]=None 
    description:Optional[str] ="Registration Otp"
    
class UserSchema(BaseModel):
    firstname:str
    lastname:str
    dob: date = Field(..., description="Date of Birth (YYYY-MM-DD)")
    address:str
    profile_pic:str
    
class SearchSchema(BaseModel):
    firstname:str
    lastname:Optional[str]=None
    
    