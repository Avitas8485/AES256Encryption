



import base64
from datetime import datetime, timedelta
import os
from pathlib import Path
import sqlite3
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class CryptoError(Exception):
    """Base class for all encryption-related exceptions."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""
    pass


class KeyRotationError(CryptoError):
    """Raised when key rotation operations fail."""
    pass


class DatabaseError(CryptoError):
    """Raised when database operations fail."""
    pass



class KeyManager:
    """Manages encryption keys, including generation, storage, and rotation."""
    KEY_ROTATION_DAYS = 30
    ITERATIONS = 100000 # High iteration count for security PBKDF2 key derivation function
    
    def __init__(self, key_storage_path: str, db_path: Optional[str] = None):
        """Initializes the KeyManager.
        
        Args:
            key_storage_path: The path to the directory where keys are stored.
            db_path: The path to the SQLite database file used to store key metadata.
        """
        self.key_storage_path = Path(key_storage_path)
        self.key_storage_path.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        if self.db_path:
            self._init_db()
            
    def _init_db(self):
        """Initializes the SQLite database."""
        if self.db_path:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS encryption_keys (
                            key_id TEXT PRIMARY KEY,
                            key_material BLOB,
                            creation_date TEXT,
                            expiry_date TEXT,
                            active INTEGER
                            )
                        ''')
                    conn.commit()
            except sqlite3.Error as e:
                    raise DatabaseError(f"Falied to initialize database: {e}")
                
    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derives an encryption key from a password using PBKDF2.
        
        Args:
            password: The password to derive the key from.
            salt: Optional salt value. If not provided, a new salt is generated.
            
        Returns:
            A tuple containing the derived key and the salt.
        """
        if salt is None:
            salt = os.urandom(16)
                
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # 32 bytes = 256 bits
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def generate_key(self) -> str:
        """Generates a new encryption key.
        
        Returns:
            The key ID.
        """
        key = Fernet.generate_key()
        key_id = base64.urlsafe_b64encode(os.urandom(16)).decode()
        creation_date = datetime.now().isoformat()
        expiry_date = (datetime.now() + timedelta(days=self.KEY_ROTATION_DAYS)).isoformat()
        
        if self.db_path:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'INSERT INTO encryption_keys VALUES (?, ?, ?, ?, ?)',
                        (key_id, key, creation_date, expiry_date, 1)
                    )
                    conn.commit()
            except sqlite3.Error as e:
                raise DatabaseError(f"Failed to insert key into database: {e}")
            
        key_path = self.key_storage_path / f"{key_id}.key"
        with open(key_path, 'wb') as f:
            f.write(key)
        return key_id
    
    def get_key(self, key_id: str) -> bytes:
        """Retrieves an encryption key.
        
        Args:
            key_id: The key ID.
            
        Returns:
            The key.
        """
        if self.db_path:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'SELECT key_material FROM encryption_keys WHERE key_id = ?',
                        (key_id,)
                    )
                    result = cursor.fetchone()
                    if result:
                        return result[0]
            except sqlite3.Error as e:
                pass # Fall back to file-based key storage if database operation fails
        
        key_path = self.key_storage_path / f"{key_id}.key"
        if key_path.exists():
            with open(key_path, 'rb') as f:
                return f.read()
            
        raise KeyRotationError(f"Key {key_id} not found")
    
    def rotate_keys(self) -> None:
        """Rotates encryption keys, deactivating expired keys and generating new ones.
        
        Raises:
            KeyRotationError: If key rotation fails.
        """
        if not self.db_path:
            raise KeyRotationError("Database path required for key rotation")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT key_id, expiry_date FROM encryption_keys WHERE active = 1")
                active_keys = cursor.fetchall()
                
                current_time = datetime.now()
                for key_id, expiry_date in active_keys:
                    expiry_date = datetime.fromisoformat(expiry_date)
                    if current_time > expiry_date:
                        cursor.execute("UPDATE encryption_keys SET active = 0 WHERE key_id = ?", (key_id,))
                new_key_id = base64.urlsafe_b64encode(os.urandom(16)).decode()
                new_key = Fernet.generate_key()
                creation_date = current_time.isoformat()
                expiry_date = (current_time + timedelta(days=self.KEY_ROTATION_DAYS)).isoformat()
                cursor.execute(
                    'INSERT INTO encryption_keys VALUES (?, ?, ?, ?, ?)',
                    (new_key_id, new_key, creation_date, expiry_date, 1)
                )
                
                key_file_path = self.key_storage_path / f"{new_key_id}.key"
                with open(key_file_path, 'wb') as f:
                    f.write(new_key)
                conn.commit()
        except (sqlite3.Error, IOError) as e:
            raise KeyRotationError(f"Failed to rotate keys: {e}")
        
    def delete_old_keys(self, days: int=90) -> None:
        """Permanently deletes keys that are older than a specified number of days.
        
        Args:
            days: The number of days after which keys should be deleted.
            
        Raises:
            KeyRotationError: If key deletion fails.
        """
        
        if not self.db_path:
            raise KeyRotationError("Database path required for key deletion")
        
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT key_id FROM encryption_keys WHERE creation_date < ? AND active = 0",
                    (cutoff_date,)
                )
                keys_to_delete = [row[0] for row in cursor.fetchall()]
                cursor.execute(
                    "DELETE FROM encryption_keys WHERE creation_date < ? AND active = 0",
                    (cutoff_date,)
                )
                conn.commit()
                
                for key_id in keys_to_delete:
                    key_file_path = self.key_storage_path / f"{key_id}.key"
                    if key_file_path.exists():
                        key_file_path.unlink()
                        
        except (sqlite3.Error, IOError) as e:
            raise KeyRotationError(f"Failed to delete old keys: {e}")
        
    def get_active_keys(self) -> List[str]:
        """Retrieves the IDs of all active keys.
        
        Returns:
            A list of key IDs.
        """
        if not self.db_path:
            return [f.stem for f in self.key_storage_path.glob("*.key")]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT key_id FROM encryption_keys WHERE active = 1")
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to retrieve active keys: {e}")
        
        

        