from datetime import datetime
from typing import Dict, Literal, Optional, Union
import pydantic
from pydantic import BaseModel, Field, validator


class KeyInfo(BaseModel):
    """Model for key information used in encryption/decryption"""
    type: Literal["password", "key_id"]
    key_id: Optional[str] = None
    salt: Optional[str] = None  # Base64 encoded salt
    
    @validator('salt', always=True)
    def validate_salt(cls, v, values):
        if values.get('type') == 'password' and not v:
            raise ValueError('Salt is required for password-based keys')
        return v
    
    @validator('key_id', always=True)
    def validate_key_id(cls, v, values):
        if values.get('type') == 'key_id' and not v:
            raise ValueError('Key ID is required for key_id-based encryption')
        return v


class EncryptedPackage(BaseModel):
    """Model for encrypted data package"""
    data: str  # Base64 encoded encrypted data
    key_id: str
    timestamp: datetime
    version: str = "1.0"


class FileMetadata(BaseModel):
    """Model for encrypted file metadata"""
    key_info: KeyInfo
    original_filename: str
    original_size: int
    encrypted: bool = True
    timestamp: datetime = Field(default_factory=datetime.now)
    encrypt_filename: bool = False
    version: str = "1.0"
    hmac: Optional[str] = None


class DecryptedFileInfo(BaseModel):
    """Model for decrypted file information"""
    original_filename: str
    original_size: int
    decrypted_path: str
    timestamp: datetime = Field(default_factory=datetime.now)