from fastapi import FastAPI,Depends, File,HTTPException, UploadFile
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
import json
from datetime import datetime, timedelta
from passlib.hash import bcrypt
import phonenumbers,re,os,smtplib,random,shutil
from sqlalchemy import and_, or_
from .database import SessionLocal,engine,Base
from sqlalchemy.orm import Session
from .model import User,Otp,Profile,SendRequest,FriendList,Room,Conversation
from .schema import OtpSchema,UserSchema,SearchSchema
# from twilio.rest import Client
from pydantic import ValidationError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

Base.metadata.create_all(engine)

SECRET_KEY = "136b00cb7a7f565315f9ca26eb5dc4f97a8bcbff9291fc5888b374a3523d0580"
ALGORITHM = "HS256"
reuseable_oauth = OAuth2PasswordBearer(
    tokenUrl="/login",
    scheme_name="JWT"
    )
def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
MAIL_USERNAME = "anjalisharma68067@gmail.com"
MAIL_PASSWORD = "xxsc jswn anmi dgvc"
MAIL_FROM = "anjalisharma68067@gmail.com"
MAIL_PORT = 587
MAIL_SERVER = "smtp.gmail.com"
MAIL_FROM_NAME = "Anjali"
MAIL_STARTTLS = False
USE_CREDENTIALS = True
VALIDATE_CERTS = True 
        
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
    raise ValueError("Twilio credentials not found in environment variables.")
# client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) 
def checkEmail(email):
    email=r'^[\w\.-]+@[\w\.-]+\.\w+$'
    email_exp = re.compile(email)
    if email_exp:
        return True
    else:
        return False
    
def create_access_token(data:dict,expires_delta:timedelta):
    to_encode =data.copy()  
    expire=datetime.utcnow()+expires_delta
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data:dict,expires_delta:timedelta):
    to_encode =data.copy()  
    expire=datetime.utcnow()+expires_delta
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token:str):
    try:
        payload=jwt.decode(token, SECRET_KEY, algorithm=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, default="Invalid Credentials:..")
         
def otp_gen():
   otp= random.randint(1000,10000) 
   return otp

def send_email(otp:int, email:str):
    subject = "Greetings Dear ..!"
    message_template = f"Your Otp :{otp} "
    msg = MIMEMultipart()
    msg['From'] = MAIL_FROM
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(message_template))
    try:
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT) 
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_USERNAME, email, msg.as_string())
        print("Email sent successfully!")
    except Exception as e:
        res = str(e)
        print("Error:", res)
        
def send_num(otp:int):
    # service = client.messages.create
    # (
    body= f'hello ,Here is your otp:--{otp}!..',
    # from_='+18778422943',
    # to='+91 8219832433'
    # )
    return{otp}
    # return service.sid

def validate_num(phone):
    try:
        parsed_number = phonenumbers.parse(phone,None)
        if phonenumbers.is_valid_number(parsed_number):
            return phonenumbers.is_valid_number(parsed_number)
    except phonenumbers.NumberParseException:
            raise ValueError("Invalid phone number format")
    
async def get_current_user(token:str = Depends(reuseable_oauth), db:Session =Depends(get_db)):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        token_data = payload
        if datetime.fromtimestamp(token_data["exp"])<datetime.now():
            raise HTTPException(
                status_code = 401,
                detail = "Token expired...",
                headers = {"WWW-Authenticate":"Bearer"}
            )
    except(jwt.JWTError, ValidationError):
        raise HTTPException(status_code = 403,
                            detail = "Credentials can't be validated...",
                            headers = {"WWW-Authenticate":"Bearer.."},
                            )
    if checkEmail(token_data["sub"]) == True:
       user = db.query(User).filter(User.email == token_data["sub"]).first()     
    else:
        user = db.query(User).filter(User.phone == token_data["sub"]).first()     
    if user is None:
        raise HTTPException(status_code=404, detail = "Could not find user") 
    return user
            
app= FastAPI(debug=True)  
          
@app.post('/sign_up')
def sign_up(info:OtpSchema, db:Session=Depends(get_db)):
    check_user=db.query(Otp).filter(and_(Otp.user_id == info.email, Otp.password == info.password)).first()
    if check_user:
        raise HTTPException(status_code = 404, detail = "User already existed..!")
    otp=otp_gen()
    user_data={}
    if info.phone:
        if validate_num(info.phone):
            send_num(otp)
            hashed_password = bcrypt.hash(info.password)
            user_data["user_id"] = info.phone
            user_data["password"] = hashed_password
    else:
        send_email(otp, info.email)
        hashed_password = bcrypt.hash(info.password)
        user_data["user_id"] = info.email
        user_data["password"] = hashed_password
    user_data["otp"] = otp
    user_data["description"] ="Otp for register User"
    otp_user = db.query(Otp).filter(Otp.user_id == user_data["user_id"]).first()
    if otp_user:
        otp_user.otp = otp
    else:
        otp_user = Otp(**user_data)
    db.add(otp_user)
    db.commit()
    db.refresh(otp_user)
    return{"Message":"Otp is sent successfully..!"}

@app.post('/confirm_otp')
def confirm_otp(otp:int, db:Session=Depends(get_db)):
    check_otp = db.query(Otp).filter(Otp.otp == otp).first()
    if check_otp is None:
        raise HTTPException(status_code=205, detail="Content not found..!")
    user_data={}
    if checkEmail(check_otp.user_id):
        user_data["email"]  = check_otp.user_id
        user_data["password"] = check_otp.password
    else:
       user_data["phone"] = check_otp.user_id
       user_data["password"] = check_otp.password 
    user_info = User(**user_data)
    db.delete(check_otp)
    db.add(user_info)
    db.commit()
    db.refresh(user_info)
    expires_delta = timedelta(days=1)
    refresh_delta = timedelta(days=30)
    access_token = create_access_token(data={"sub":user_info.email}, expires_delta=expires_delta) 
    refresh_token = create_refresh_token(data={"sub":user_info.email},expires_delta=refresh_delta)
    return {"access_token": access_token, "refesh_token":refresh_token, "token_type": "bearer",
          "Message":"Please Update Your Information first..."}

@app.patch('/profile_update')
def update_user(info:UserSchema, db:Session=Depends(get_db), user:User=Depends(get_current_user)) :
    ex_user=db.query(Profile).filter(Profile.user_id == user.id).first()
    if ex_user:
        raise HTTPException(status_code = 404, detail="seems you're profile already updated..!")
    user_data={}
    user_data["firstname"] = info.firstname
    user_data["lastname"] = info.lastname
    user_data["dob"] = info.dob
    year=info.dob.year
    current_year = 2024
    user_data["age"] =  current_year - year
    user_data["user"] = user
    user_data["address"] = info.address
    if info.profile_pic:
        user_data["profile_pic"] = info.profile_pic
    else :
       user_data["profile_pic"]  = f"app/media/IMG_20220516_133539295.PORTRAIT.jpg"
    user_detail=Profile(**user_data)  
    db.add(user_detail)
    db.commit()
    db.refresh(user_detail)
    return{"Message":"Your details successfully submitted...!"}  
  
app.mount('/app/media', StaticFiles(directory='app/media'),'Images')
@app.patch('/update_pic')
def update_profile(firstname:str, lastname:str, db:Session = Depends(get_db), uploaded_file:UploadFile = File(...)):
    check_user = db.query(Profile).filter(or_(Profile.firstname == firstname, Profile.lastname == lastname)).first()
    path = f"app/media/{uploaded_file.filename}"
    with open(path, 'w+b') as file:
       shutil.copyfileobj(uploaded_file.file, file)
    if check_user:
        check_user.profile_pic = path
    file_type = uploaded_file.content_type
    if file_type not in["image/png", "image/jpeg", "image/jpg", "image/heic", "image/heif", "image/heics", "png",
                          "jpeg", "jpg", "heic", "heif", "heics"]:
           return {"Message": "Not an image format. Please recheck."}
    db.add(check_user)
    db.commit()
    db.refresh(check_user)
    return{"Message":"Image Uploaded Successfully..!",
              "filename": check_user.profile_pic,
              "file_type": file_type}
                     
@app.post('/login')
def login(info:OtpSchema, db:Session=Depends(get_db)):
    user_id = info.phone if info.phone else info.email
    verify_user = db.query(User).filter(User.email == user_id).first()
    if verify_user and bcrypt.verify(info.password, verify_user.password): 
          expires_delta = timedelta(days=2)
          refresh_delta = timedelta(days=30)
          access_token = create_access_token(data={"sub":verify_user.email}, expires_delta=expires_delta) 
          refresh_token = create_refresh_token(data={"sub":verify_user.email}, expires_delta=refresh_delta)
          return{"access_token": access_token, "refresh_token":refresh_token, "token_type": "bearer","Message":"Logged in Successfully..!"}
    elif verify_user:
        raise HTTPException(status_code=401, detail = "Wrong Password..")
    else:
        raise HTTPException(status_code=401, detail = "Not existed user..Please signup first")
        
@app.post('/forgot_password')
def forgot_password(email:str, db:Session=Depends(get_db)):
    verify_user= db.query(User).filter(User.email == email).first()
    if verify_user:
        otp=otp_gen()
        user_data={}
        send_email(otp, verify_user.email)
        user_data["user_id"] = verify_user.email
        user_data["otp"] = otp
        user_data["description"] ="Update Password"
        otp_ex = db.query(Otp).filter(Otp.otp == user_data["otp"]).first()
        if otp_ex:
             otp_ex.otp = otp 
        else:
            otp_ex = Otp(**user_data)
        db.add( otp_ex)
        db.commit()
        db.refresh( otp_ex)
        return{"Message":"Otp has sent please check and update password..!"}
    else:
        return{"Message":"Please Sign_up again.."}

@app.post('/password_update')
def password_update(otp:int, email:str, new_password:str, db:Session=Depends(get_db)):
    check_otp = db.query(Otp).filter(Otp.otp == otp).first()
    if check_otp is None:
        raise HTTPException(status_code=404, detail="Ohh..OTP mismatched..!") 
    else:
        hashed_password = bcrypt.hash(new_password)
        check_mail = db.query(User).filter(User.email == email).first()
        if check_mail:
            check_mail.password = hashed_password
            db.add(check_mail)
            db.delete(check_otp)
            db.commit()
            db.refresh(check_mail)
            return{"Message":"Your Password updated successfully..!Login Now"}
        else:
            raise HTTPException(status_code=404, detail ="Email with this i'd not found..Please register first.")
     
@app.post('/search_user')
def search_user(info:SearchSchema, db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    check_user = db.query(Profile).filter(and_(Profile.firstname == info.firstname, Profile.lastname == info.lastname)).first()
    if check_user is None:
        raise HTTPException(status_code = 400,detail="No Record Found..!")
    else:
        check_list = []
        checkfriend = db.query(FriendList).filter(FriendList.user_id == user.id).first()
        if checkfriend is None:
            result = f"{check_user.firstname} {check_user.lastname}"
            return{
                "Message":"Result Found",
                "id":check_user.id,
                "Name":result,
                "age":check_user.age,
                "profile_pic":check_user.profile_pic
                }
        else:
            if isinstance(checkfriend.blocked_list,str):
                check_list = json.loads(checkfriend.blocked_list)
            else:
                 check_list = checkfriend.blocked_list
            if check_user.id in check_list:
                return{"Message":"User not available"}
          
@app.post('/send_request')
def send_request(receiver_id:int, db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    user_data={}
    check_profile = db.query(Profile).filter(Profile.user_id == receiver_id).first()
    if check_profile:
        check_ex = db.query(SendRequest).filter(and_(or_(SendRequest.sender_id == user.id, SendRequest.receiver_id  == user.id)), (or_(SendRequest.sender_id == check_profile.user_id, SendRequest.receiver_id == check_profile.user_id))).first()
        if check_ex:                                             
             raise HTTPException(status_code = 404, detail="You're already friends.")
        else:   
            user_data["sender_id"] = user.id
            user_data["receiver_id"] = check_profile.user_id
            user_detail = SendRequest(**user_data)
            db.add(user_detail)
            db.commit()
            db.refresh(user_detail)
            return{"Message":"Request Sent Successfully.."}
    else:
        return{"Message":"Something went gone..!"}
   
@app.get('/view_request')
def get_send_request(db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    friend_request = db.query(SendRequest).filter(SendRequest.receiver_id == user.id)
    if friend_request == []:
        return {"No request here..!"}   
    else:
        results = [suser for suser in friend_request]
        return{"Message":"You Got Request From..",
               "Sender_id as":results}
        

@app.post('/accept_request')
def accept_request(id:int, db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    check_user = db.query(SendRequest).filter(and_(SendRequest.sender_id == id, SendRequest.receiver_id == user.id)).first()
    user_data = {}
    friend_list = []
    if check_user:
        check_user.status = True
        db.add(check_user)
        db.commit()
        db.refresh(check_user)  
        sender = check_user.sender_id 
        check_ex= db.query(FriendList).filter(FriendList.user_id == user.id).first()
        if check_ex:
            if check_ex.friends:
                friend_list = json.loads(check_ex.friends)
                block_list =json.loads(check_ex.blocked_list)
                if sender in friend_list:
                    raise HTTPException(status_code = 404, detail ="Umm, seems already friends.!")
                if sender in block_list:
                    raise HTTPException(status_code = 404, detail="Something Went wrong..!")
                friend_list.append(sender)
                check_ex.friends = json.dumps(friend_list)   
            else:
                check_ex.friends = json.dumps([check_user.sender_id])
        else:
            user_data["user_id"] = user.id   
            user_data["friends"] = json.dumps([check_user.sender_id]) 
            user_data["blocked_list"] = []
            check_ex = FriendList(**user_data)
        db.add(check_ex)
        db.commit()
        db.refresh(check_ex)         
        user_detail = db.query(FriendList).filter(FriendList.user_id == check_user.sender_id).first()
        if user_detail:
            if user_detail.friends:
                friend_list = json.loads(user_detail.friends)
                sender = user.id
                friend_list.append(sender)
                user_detail.friends = json.dumps(friend_list)    
            else:
                user_detail.friends = json.dumps([user.id])
        else:
            user_data["user_id"] = check_user.sender_id  
            user_data["friends"]=  json.dumps([user.id]) 
            user_data["blocked_list"] = []
            user_detail = FriendList(**user_data)
        db.add(user_detail)
        db.commit()
        db.refresh(user_detail)         
        return{"Message":"New friend added in your list..!"}
    return{"Message":"There is no request"} 


@app.post('/block_user')
def block_user(id:int, db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    user_data={}
    check_user=db.query(SendRequest).filter(SendRequest.sender_id == id).first()
    if check_user:
        check_ex =db.query(FriendList).filter(FriendList.user_id == user.id).first()
        if check_ex:
            if check_ex.blocked_list is None or []:  
                check_ex.blocked_list =json.dumps([check_user.sender_id])
            else:
                if isinstance(check_ex.blocked_list,str):
                    block_user = json.loads(check_ex.blocked_list)
                else:
                    block_user = check_ex.blocked_list
                if check_user.sender_id in block_user:
                    raise HTTPException(status_code = 404, detail = "Already Blocked User ..!")
                block_user.append(check_user.sender_id)  
                check_ex.blocked_list = json.dumps(block_user)
            db.add(check_ex)
            db.commit()
            db.refresh(check_ex)    
        else:
            user_data["user_id"] = user.id
            user_data["blocked_list"] = json.dumps([check_user.sender_id])
            user_detail = FriendList(**user_data)
            db.add(user_detail)
            db.commit()
            db.refresh(user_detail)
        
        
        if check_ex.friends is not None:
            sender_find_list = []
            friend_list = json.loads(check_ex.friends)
            check_sender=db.query(FriendList).filter(FriendList.user_id == check_user.sender_id).first()
            if check_sender:
                sender_find_list =json.loads(check_sender.friends)
                if len(sender_find_list) >0 and user.id in sender_find_list:
                    sender_find_list.remove(user.id)
                    check_sender.friends = sender_find_list
            if check_user.sender_id in friend_list:
                friend_list.remove(check_user.sender_id)
                check_ex.friends = json.dumps(friend_list)
                db.add(check_ex)
                db.commit()
                db.refresh(check_ex) 
            db.add(check_sender)
            db.commit()
            db.refresh(check_sender)
        return{"Message":"Successfully blocked.You can unblock any time if you want..!"}
    
@app.post('/unblock_user')
def unblock_user(user_id:int, user:User=Depends(get_current_user), db:Session=Depends(get_db)):
    check_user =db.query(FriendList).filter(FriendList.user_id== user.id).first()
    unblock_user=[]
    if check_user:
        if not check_user.blocked_list:
            raise HTTPException(status_code=404,detail="Block list is empty")
        else:
            if isinstance(check_user.blocked_list, str):
                unblock_user =json.loads(check_user.blocked_list)
            else:
                unblock_user =check_user.blocked_list
            if user_id in unblock_user :
                unblock_user.remove(user_id)
            check_user.blocked_list = json.dumps(unblock_user)
            db.add(check_user)
            db.commit()
            db.refresh(check_user)   
            return{"Message":"User Unblock now.."}
       
@app.get('/getfriendslist')
def getfriend(db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    getfriendslist= db.query(FriendList).filter(FriendList.user_id == user.id).first()
    if getfriendslist:
        return{"Friendlist":getfriendslist.friends}

@app.get('/getblockeduser')
def getblockuser(db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    check_user = db.query(FriendList).filter(FriendList.user_id == user.id).first()
    if check_user:
        return{"blockedlist":check_user.blocked_list}
    else:
        raise HTTPException(status_code=404,detail="No user here...")

@app.post('/user_room')
def user_room(friend_id:int, db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    check_user = db.query(FriendList).filter(FriendList.user_id == user.id).first()
    user_data={}
    fav_user=[]
    if check_user :
        if isinstance(check_user.friends,str):
            fav_user = json.loads(check_user.friends)
        else:
            fav_user = check_user.friends
        if friend_id in fav_user:
            data = str(check_user.user_id) + str(friend_id)   
        check_list = db.query(Room).filter(and_(or_(Room.sender_id== user.id,Room.receiver_id == user.id)),(or_(Room.receiver_id== friend_id,Room.sender_id == friend_id))).first()
        if check_list:
            user_data["room_id"] = check_list.room_id
            user_data["sender_id"] = user.id 
            user_data["receiver_id"] = friend_id   
        else:
            user_data["room_id"] =int(data)
            user_data["sender_id"] = user.id 
            user_data["receiver_id"] = friend_id
        check_ex =db.query(Room).filter(and_(Room.sender_id == user.id,Room.receiver_id == friend_id)).first()
        if check_ex:
            raise HTTPException(status_code = 404, detail = "User already existed..!")
        else:
            detail = Room(**user_data)
            db.add(detail)
            db.commit()
            db.refresh(detail)
            return{"Message":"You are ready for conversation now...",
                    "Room_id":detail}
    else:
        raise HTTPException(status_code = 404, detail = "No user existed..")
                   
@app.post('/chat_list')
def chat_list(db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    friend=[]
    check_current_user = db.query(FriendList).filter(FriendList.user_id == user.id).first()
    if check_current_user:
        for getfriend in json.loads(check_current_user.friends):
            user_info={}
          
            user_data = db.query(User).filter(User.id == getfriend).first()
            if user_data:
                user_info["user_id"] = user_data.id
                user_info["firstname"] = user_data.profile[0].firstname
                user_info["lastname"] = user_data.profile[0].lastname
                user_info["age"] = user_data.profile[0].age
                user_info["profile_pic"] = user_data.profile[0].profile_pic
                friend.append(user_info)
        return{"Msg":friend}   
    getroom = db.query(Room).filter(Room.room_id == room_id).first()
    if getroom is None:
        raise HTTPException(status_code=404, detail="Room not found")
    if getroom.sender_id == user.id:
        user_data["msg"] = msg
    else:   
        user_data["msg"] = msg
    if user_status == True:
        user_data["status"] = "Read"
    else:
        user_data["status"] = "Delivered"
    user_data["room_id"] = room_id    
    user_detail = Conversation(**user_data)
    db.add(user_detail)
    db.commit()
    db.refresh(user_detail)
    return{"Message":"Message Sent Successfully..!"}
  
  
          
                                       
     