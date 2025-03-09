



import base64
from datetime import datetime
import json
from pathlib import Path
import shutil
from typing import Any, Dict, Optional, Union
from key_manager import CryptoError, DecryptionError, KeyManager
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken


class Encryptor:
    """Provides encryption and decryption methods for files and data."""
    
    def __init__(self, key_manager: KeyManager):
        """Initializes the Encryptor.
        
        Args:
            key_manager: The KeyManager instance to use for encryption and decryption.
        """
        self.key_manager = key_manager
        
    def encrypt_data(self, data: Union[str, bytes], key_id: Optional[str] = None) -> Dict[str, str]:
        """Encrypts data with Fernet (AES-256) 
        
        Args:
            data: The data to encrypt.
            key_id: Optional key ID to use for encryption (generates a new key if not provided).
            
        Returns:
            A dictionary containing the encrypted data and metadata.
        """
        if key_id is None:
            key_id = self.key_manager.generate_key()
        
        key = self.key_manager.get_key(key_id)
        f = Fernet(key)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        encrypted_data = f.encrypt(data)
        timestamp = datetime.now().isoformat()
        
        result = {
            'data': base64.b64encode(encrypted_data).decode('utf-8'),
            'key_id': key_id,
            'timestamp': timestamp,
            'version': '1.0'
        }
        
        return result
    
    def decrypt_data(self, encrypted_package: Dict[str, str]) -> bytes:
        """Decrypts data with Fernet (AES-256).
        
        Args:
            encrypted_package: A dictionary containing the encrypted data and metadata.
            
        Returns:
            The decrypted data.
        
        Raises:
            DecryptionError: If the data cannot be decrypted.
        """
        try:
            key_id = encrypted_package['key_id']
            encrypted_data = base64.b64decode(encrypted_package['data'])
            key = self.key_manager.get_key(key_id)
            f = Fernet(key)
            return f.decrypt(encrypted_data)
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt data: {e}")
        
    def encrypt_file(self, input_path: str, output_path: Optional[str] = None, password: Optional[str] = None,
                     key_id: Optional[str] = None, chunk_size: int = 4096, encrypt_filename: bool = False) -> Dict[str, Any]:
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
            A dictionary containing the metadata of the encrypted file.
            
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
            key_info = {'type': 'password', 'salt': base64.b64encode(salt).decode()}
        else:
            if key_id is None:
                key_id = self.key_manager.generate_key()
            key = self.key_manager.get_key(key_id)
            f = Fernet(key)
            key_info = {'type': 'key_id', 'key_id': key_id}
            
        filename = _input_path.name
        file_size = _input_path.stat().st_size
        timestamp = datetime.now().isoformat()
        
        if encrypt_filename:
            filename = base64.b64encode(f.encrypt(filename.encode())).decode()  
            
        metadata = {
            'key_info': key_info,
            'original_filename': filename,
            'original_size': file_size,
            'encrypted': True,
            'timestamp': timestamp,
            'encrypt_filename': encrypt_filename,
            'version': '1.0',
            'hmac': None  # Will be filled in later
        }
        
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
                json.dump(metadata, meta_file)
                
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
                     password: Optional[str] = None, chunk_size: int = 4096) -> Dict[str, Any]:
        """
        Decrypts a file that was encrypted with encrypt_file().
        
        Args:
            input_path: The path to the encrypted file.
            output_path: The path to save the decrypted file (defaults to input_path without '.enc').
            password: Optional password to use for decryption.
            chunk_size: The size of each chunk read from the input file.
            
        Returns:
            A dictionary containing the metadata of the decrypted file.
            
        Raises:
            DecryptionError: If the file cannot be decrypted.
            IOError: If the input file cannot be read or the output file cannot be written.
        """
        _input_path = Path(input_path)
        metadata_path = _input_path.with_suffix('.meta')
        
        try:
            with open(metadata_path, 'r') as meta_file:
                metadata: dict = json.load(meta_file)
        except (IOError, json.JSONDecodeError) as e:
            raise IOError(f"Failed to read metadata: {e}")
        
        if output_path is None:
            file_name = metadata['original_filename']
            if metadata.get('encrypt_filename', False):
                if metadata['key_info']['type'] == 'password':
                    if password is None:
                        raise DecryptionError("Password required to decrypt file")
                    salt = base64.b64decode(metadata['key_info']['salt'])
                    key, _ = self.key_manager.derive_key_from_password(password, salt)
                    f = Fernet(key)
                else:
                    key_id = metadata['key_info']['key_id']
                    key = self.key_manager.get_key(key_id)
                    f = Fernet(key)
                    
                encrypted_filename = base64.b64decode(file_name.encode())
                file_name = f.decrypt(encrypted_filename).decode()
                
            _output_path = _input_path.parent / file_name
        else:
            _output_path = Path(output_path)
            
        if metadata['key_info']['type'] == 'password':
            if password is None:
                raise DecryptionError("Password required to decrypt file")
            salt = base64.b64decode(metadata['key_info']['salt'])
            key, _ = self.key_manager.derive_key_from_password(password, salt)
            f = Fernet(key)
        else:
            key_id = metadata['key_info']['key_id']
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
            return {
                'original_filename': metadata['original_filename'],
                'original_size': metadata['original_size'],
                'decrypted_path': str(output_path),
                'timestamp': datetime.now().isoformat()
            }
            
        except (IOError, OSError) as e:
            if temp_output.exists():
                temp_output.unlink()    
            raise IOError(f"Failed to decrypt file: {e}")
        

            
                
                
