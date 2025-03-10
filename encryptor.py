import base64
from datetime import datetime
import json
from pathlib import Path
import shutil
from typing import Any, Dict, Optional, Union

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

from key_manager import CryptoError, DecryptionError, KeyManager
from models import EncryptedPackage, FileMetadata, KeyInfo, DecryptedFileInfo


class Encryptor:
    """Provides encryption and decryption methods for files and data."""
    
    def __init__(self, key_manager: KeyManager):
        """Initializes the Encryptor.
        
        Args:
            key_manager: The KeyManager instance to use for encryption and decryption.
        """
        self.key_manager = key_manager
        
    def encrypt_data(self, data: Union[str, bytes], key_id: Optional[str] = None) -> EncryptedPackage:
        """Encrypts data with Fernet (AES-256) 
        
        Args:
            data: The data to encrypt.
            key_id: Optional key ID to use for encryption (generates a new key if not provided).
            
        Returns:
            An EncryptedPackage containing the encrypted data and metadata.
        """
        if key_id is None:
            key_id = self.key_manager.generate_key()
        
        key = self.key_manager.get_key(key_id)
        f = Fernet(key)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        encrypted_data = f.encrypt(data)
        
        result = EncryptedPackage(
            data=base64.b64encode(encrypted_data).decode('utf-8'),
            key_id=key_id,
            timestamp=datetime.now(),
            version='1.0'
        )
        
        return result
    
    def decrypt_data(self, encrypted_package: EncryptedPackage) -> bytes:
        """Decrypts data with Fernet (AES-256).
        
        Args:
            encrypted_package: An EncryptedPackage containing the encrypted data and metadata.
            
        Returns:
            The decrypted data.
        
        Raises:
            DecryptionError: If the data cannot be decrypted.
        """
        try:
            key_id = encrypted_package.key_id
            encrypted_data = base64.b64decode(encrypted_package.data)
            key = self.key_manager.get_key(key_id)
            f = Fernet(key)
            return f.decrypt(encrypted_data)
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt data: {e}")
        
    def encrypt_file(self, input_path: str, output_path: Optional[str] = None, password: Optional[str] = None,
                     key_id: Optional[str] = None, chunk_size: int = 4096, encrypt_filename: bool = False) -> FileMetadata:
        """
        Encrypts a file with Fernet (AES-256).
        
        Args:
            input_path: The path to the input file.
            output_path: The path to save the encrypted file (defaults to input_path + '.enc').
            password: Optional password to use for encryption.
            key_id: Optional key ID to use for encryption (generates a new key if not provided).
            chunk_size: The size of each chunk read from the input file.
            encrypt_filename: Whether to encrypt the filename in the metadata.
            
        Returns:
            FileMetadata containing the metadata of the encrypted file.
            
        Raises:
            IOError: If the input file cannot be read or the output file cannot be written.
            CryptoError: If the file cannot be encrypted.
        """
        
        _input_path = Path(input_path)
        
        if output_path is None:
            output_path = str(_input_path) + '.enc'
        _output_path = Path(output_path)
        
        if password is not None:
            key, salt = self.key_manager.derive_key_from_password(password)
            f = Fernet(key)
            key_info = KeyInfo(
                type='password',
                salt=base64.b64encode(salt).decode()
            )
        else:
            if key_id is None:
                key_id = self.key_manager.generate_key()
            key = self.key_manager.get_key(key_id)
            f = Fernet(key)
            key_info = KeyInfo(
                type='key_id',
                key_id=key_id
            )
            
        filename = _input_path.name
        file_size = _input_path.stat().st_size
        
        if encrypt_filename:
            filename = base64.b64encode(f.encrypt(filename.encode())).decode()  
            
        metadata = FileMetadata(
            key_info=key_info,
            original_filename=filename,
            original_size=file_size,
            encrypted=True,
            timestamp=datetime.now(),
            encrypt_filename=encrypt_filename,
            version='1.0',
            hmac=None  # Will be filled in later
        )
        
        temp_output_path = None  # Initialize before the try block
        try:
            temp_output_path = _output_path.with_suffix('.tmp')
            with open(_input_path, 'rb') as f_in, open(temp_output_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    encrypted_chunk = f.encrypt(chunk)
                    f_out.write(encrypted_chunk)
                    
            metadata_path = _output_path.with_suffix('.meta')
            with open(metadata_path, 'w') as meta_file:
                json.dump(metadata.dict(), meta_file)
                
            shutil.move(temp_output_path, _output_path)
            return metadata
        except (IOError, OSError) as e:
            if temp_output_path is not None and temp_output_path.exists():
                temp_output_path.unlink()
        
            raise IOError(f"Failed to encrypt file: {e}")
        except Exception as e:
            if temp_output_path is not None and temp_output_path.exists():
                temp_output_path.unlink()
            raise CryptoError(f"Failed to encrypt file: {e}")
        
    def decrypt_file(self, input_path: str, output_path: Optional[str] = None, 
                     password: Optional[str] = None, chunk_size: int = 4096) -> DecryptedFileInfo:
        """
        Decrypts a file that was encrypted with encrypt_file().
        
        Args:
            input_path: The path to the encrypted file.
            output_path: The path to save the decrypted file (defaults to input_path without '.enc').
            password: Optional password to use for decryption.
            chunk_size: The size of each chunk read from the input file.
            
        Returns:
            DecryptedFileInfo containing information about the decrypted file.
            
        Raises:
            DecryptionError: If the file cannot be decrypted.
            IOError: If the input file cannot be read or the output file cannot be written.
        """
        _input_path = Path(input_path)
        metadata_path = _input_path.with_suffix('.meta')
        
        try:
            with open(metadata_path, 'r') as meta_file:
                metadata_dict = json.load(meta_file)
                metadata = FileMetadata.parse_obj(metadata_dict)
        except (IOError, json.JSONDecodeError) as e:
            raise IOError(f"Failed to read metadata: {e}")
        
        if output_path is None:
            file_name = metadata.original_filename
            if metadata.encrypt_filename:
                if metadata.key_info.type == 'password':
                    if password is None:
                        raise DecryptionError("Password required to decrypt file")
                    if metadata.key_info.salt is None:
                        raise DecryptionError("Salt required for password-based keys")
                    salt = base64.b64decode(metadata.key_info.salt)
                    key, _ = self.key_manager.derive_key_from_password(password, salt)
                    f = Fernet(key)
                else:
                    key_id = metadata.key_info.key_id
                    if key_id is None:
                        raise DecryptionError("Key ID required for key-based encryption")
                    key = self.key_manager.get_key(key_id)
                    f = Fernet(key)
                    
                encrypted_filename = base64.b64decode(file_name.encode())
                file_name = f.decrypt(encrypted_filename).decode()
                
            _output_path = _input_path.parent / file_name
        else:
            _output_path = Path(output_path)
            
        if metadata.key_info.type == 'password':
            if password is None:
                raise DecryptionError("Password required to decrypt file")
            if metadata.key_info.salt is None:
                raise DecryptionError("Salt required for password-based keys")
            salt = base64.b64decode(metadata.key_info.salt)
            key, _ = self.key_manager.derive_key_from_password(password, salt)
            f = Fernet(key)
        else:
            key_id = metadata.key_info.key_id
            if key_id is None:
                raise DecryptionError("Key ID required for key-based encryption")
            try:
                key = self.key_manager.get_key(key_id)
                f = Fernet(key)
            except KeyError as e:
                raise DecryptionError(f"Key not found: {e}")
        temp_output = _output_path.with_suffix('.tmp')
        
        try:
            with open(input_path, 'rb') as f_in, open(temp_output, 'wb') as f_out:
                while True:
                    encrypted_chunk = f_in.read(chunk_size + 100) # Add extra bytes for Fernet overhead
                    if not encrypted_chunk:
                        break
                    try:
                        decrypted_chunk = f.decrypt(encrypted_chunk)
                        f_out.write(decrypted_chunk)
                    except InvalidToken as e:
                        temp_output.unlink()
                        raise DecryptionError(f"Failed to decrypt file: {e}")
            
            shutil.move(temp_output, _output_path)
            return DecryptedFileInfo(
                original_filename=metadata.original_filename,
                original_size=metadata.original_size,
                decrypted_path=str(_output_path),
                timestamp=datetime.now()
            )
            
        except (IOError, OSError) as e:
            if temp_output.exists():
                temp_output.unlink()    
            raise IOError(f"Failed to decrypt file: {e}")
    
    def encrypt_db_field(self, value: Any, key_id: Optional[str] = None) -> str:
        """
        Encrypts a database field value.
        
        Args:
            value: The value to encrypt.
            key_id: Optional key ID to use for encryption (generates a new key if not provided).
            
        Returns:
            Base64 encoded string with encrypted data.
            
        Raises:
            CryptoError: If the value cannot be encrypted.
        """
        try:
            # Convert value to string if it's not already
            if not isinstance(value, (str, bytes)):
                value = str(value)
                
            # Encrypt the data
            encrypted_package = self.encrypt_data(value, key_id)
            
            # Return a packed string with key_id and encrypted data
            return json.dumps({
                "key_id": encrypted_package.key_id,
                "data": encrypted_package.data,
                "version": encrypted_package.version
            })
        except Exception as e:
            raise CryptoError(f"Failed to encrypt field value: {e}")
    
    def decrypt_db_field(self, encrypted_value: str) -> str:
        """
        Decrypts a database field value.
        
        Args:
            encrypted_value: The encrypted value, as returned by encrypt_db_field.
            
        Returns:
            The decrypted value as a string.
            
        Raises:
            DecryptionError: If the value cannot be decrypted.
        """
        try:
            # Parse the encrypted value
            encrypted_data = json.loads(encrypted_value)
            
            # Create an EncryptedPackage
            package = EncryptedPackage(
                data=encrypted_data["data"],
                key_id=encrypted_data["key_id"],
                timestamp=datetime.now(),
                version=encrypted_data.get("version", "1.0")
            )
            
            # Decrypt the data
            decrypted_data = self.decrypt_data(package)
            
            # Return the decrypted data as a string
            return decrypted_data.decode('utf-8')
        except json.JSONDecodeError:
            raise DecryptionError("Invalid encrypted field format")
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt field value: {e}")
            
    def sqlite_encrypt_db(self, db_path: str, tables_fields_config: Dict[str, list], 
                          key_id: Optional[str] = None, backup: bool = True) -> Dict[str, int]:
        """
        Encrypts specified fields in a SQLite database.
        
        Args:
            db_path: Path to the SQLite database file
            tables_fields_config: Dict mapping table names to lists of field names to encrypt
            key_id: Optional key ID to use for encryption
            backup: Whether to create a backup of the database before modifying
            
        Returns:
            Dict with statistics about encrypted fields
            
        Raises:
            CryptoError: If the database fields cannot be encrypted
        """
        import sqlite3
        try:
            
            
            _db_path = Path(db_path)
            
            # Create backup if requested
            if backup:
                backup_path = f"{db_path}.bak"
                shutil.copy2(db_path, backup_path)
            
            stats = {"fields_encrypted": 0}
            
            # Connect to the database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Process each table and its fields
            for table, fields in tables_fields_config.items():
                # Get all rows from the table
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table})")
                columns_info = cursor.fetchall()
                column_names = [col[1] for col in columns_info]
                
                # Check if all specified fields exist
                for field in fields:
                    if field not in column_names:
                        raise CryptoError(f"Field {field} not found in table {table}")
                
                # Process each row
                for row in rows:
                    row_dict = dict(zip(column_names, row))
                    row_id = row_dict.get('id', row_dict.get('ID', row_dict.get('Id')))
                    
                    if not row_id:
                        continue  # Skip rows without ID
                    
                    # Build update query
                    updates = []
                    params = []
                    
                    for field in fields:
                        if row_dict[field] is not None:
                            updates.append(f"{field} = ?")
                            encrypted_value = self.encrypt_db_field(row_dict[field], key_id)
                            params.append(encrypted_value)
                            stats["fields_encrypted"] += 1
                    
                    if updates:
                        update_query = f"UPDATE {table} SET {', '.join(updates)} WHERE id = ?"
                        params.append(row_id)
                        cursor.execute(update_query, params)
            
            # Commit changes
            conn.commit()
            conn.close()
            
            return stats
        
        except sqlite3.Error as e:
            raise CryptoError(f"SQLite error during encryption: {e}")
        except Exception as e:
            raise CryptoError(f"Failed to encrypt database fields: {e}")
    
    def sqlite_decrypt_db(self, db_path: str, tables_fields_config: Dict[str, list], 
                          backup: bool = True) -> Dict[str, int]:
        """
        Decrypts specified fields in a SQLite database.
        
        Args:
            db_path: Path to the SQLite database file
            tables_fields_config: Dict mapping table names to lists of field names to decrypt
            backup: Whether to create a backup of the database before modifying
            
        Returns:
            Dict with statistics about decrypted fields
            
        Raises:
            DecryptionError: If the database fields cannot be decrypted
        """
        import sqlite3
        try:
            
            _db_path = Path(db_path)
            
            # Create backup if requested
            if backup:
                backup_path = f"{db_path}.bak"
                shutil.copy2(db_path, backup_path)
            
            stats = {"fields_decrypted": 0}
            
            # Connect to the database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Process each table and its fields
            for table, fields in tables_fields_config.items():
                # Get all rows from the table
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table})")
                columns_info = cursor.fetchall()
                column_names = [col[1] for col in columns_info]
                
                # Check if all specified fields exist
                for field in fields:
                    if field not in column_names:
                        raise DecryptionError(f"Field {field} not found in table {table}")
                
                # Process each row
                for row in rows:
                    row_dict = dict(zip(column_names, row))
                    row_id = row_dict.get('id', row_dict.get('ID', row_dict.get('Id')))
                    
                    if not row_id:
                        continue  # Skip rows without ID
                    
                    # Build update query
                    updates = []
                    params = []
                    
                    for field in fields:
                        if row_dict[field] is not None:
                            try:
                                updates.append(f"{field} = ?")
                                decrypted_value = self.decrypt_db_field(row_dict[field])
                                params.append(decrypted_value)
                                stats["fields_decrypted"] += 1
                            except DecryptionError:
                                # Skip fields that aren't actually encrypted
                                continue
                    
                    if updates:
                        update_query = f"UPDATE {table} SET {', '.join(updates)} WHERE id = ?"
                        params.append(row_id)
                        cursor.execute(update_query, params)
            
            # Commit changes
            conn.commit()
            conn.close()
            
            return stats
        
        except sqlite3.Error as e:
            raise DecryptionError(f"SQLite error during decryption: {e}")
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt database fields: {e}")





