from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class User(BaseModel):
    id: Optional[int] = None
    email: str
    doc_number: Optional[str] = None
    password: Optional[str] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    loggedin: Optional[bool] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config():
        from_attributes = True

class UserLogin(BaseModel):
    email: str
    password: str

class PassRecovery(BaseModel):
    email: str
    document: str
    new_pass: str
