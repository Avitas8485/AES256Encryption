import json
import os
import shutil
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

from encryptor import Encryptor
from key_manager import KeyManager, CryptoError, DecryptionError
from models import EncryptedPackage, FileMetadata

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StorageAdapter:
    """Base class for storage adapters"""
    
    def __init__(self, encryptor: Encryptor):
        """Initialize the storage adapter.
        
        Args:
            encryptor: The encryptor to use for encryption/decryption operations
        """
        self.encryptor = encryptor

    def encrypt_storage(self):
        """Encrypt the storage"""
        raise NotImplementedError("Subclasses must implement encrypt_storage")
    
    def decrypt_storage(self):
        """Decrypt the storage"""
        raise NotImplementedError("Subclasses must implement decrypt_storage")


class ObsidianVaultAdapter(StorageAdapter):
    """Adapter for encrypting/decrypting Obsidian vaults"""
    
    def __init__(self, encryptor: Encryptor, vault_path: str):
        """Initialize the Obsidian vault adapter.
        
        Args:
            encryptor: The encryptor to use for encryption/decryption operations
            vault_path: Path to the Obsidian vault directory
        """
        super().__init__(encryptor)
        self.vault_path = Path(vault_path)
        
        # Verify that the path exists and is a directory
        if not self.vault_path.exists():
            raise ValueError(f"Vault path does not exist: {vault_path}")
        if not self.vault_path.is_dir():
            raise ValueError(f"Vault path is not a directory: {vault_path}")
    
    def encrypt_vault(self, 
                     output_path: Optional[str] = None, 
                     include_patterns: List[str] = ["*.md"], 
                     exclude_patterns: List[str] = [".obsidian/*"], 
                     key_id: Optional[str] = None,
                     password: Optional[str] = None) -> Dict[str, Any]:
        """Encrypt an Obsidian vault.
        
        Args:
            output_path: Path to save the encrypted vault (defaults to vault_path + '_encrypted')
            include_patterns: List of file patterns to include (glob format)
            exclude_patterns: List of file patterns to exclude (glob format)
            key_id: Optional key ID to use for encryption
            password: Optional password to use for encryption
            
        Returns:
            Dictionary with encryption statistics
        """
        if output_path is None:
            output_path = str(self.vault_path) + "_encrypted"
        
        output_dir = Path(output_path)
        os.makedirs(output_dir, exist_ok=True)
        
        stats = {
            "files_processed": 0,
            "files_encrypted": 0,
            "bytes_encrypted": 0,
            "errors": 0,
            "skipped_files": 0,
            "start_time": datetime.now(),
        }
        
        # Create metadata file
        metadata = {
            "source_vault": str(self.vault_path),
            "encryption_date": datetime.now().isoformat(),
            "encrypted_files": []
        }
        
        # Walk through the vault directory
        for root, dirs, files in os.walk(self.vault_path):
            rel_path = Path(root).relative_to(self.vault_path)
            current_output_dir = output_dir / rel_path
            os.makedirs(current_output_dir, exist_ok=True)
            
            for file in files:
                stats["files_processed"] += 1
                file_path = Path(root) / file
                rel_file_path = file_path.relative_to(self.vault_path)
                
                # Check if file should be included/excluded
                should_process = False
                for pattern in include_patterns:
                    if file_path.match(pattern):
                        should_process = True
                        break
                
                for pattern in exclude_patterns:
                    if file_path.match(pattern):
                        should_process = False
                        break
                
                if not should_process:
                    # Copy file as is
                    output_file = current_output_dir / file
                    shutil.copy2(file_path, output_file)
                    stats["skipped_files"] += 1
                    continue
                
                # Encrypt the file
                output_file = current_output_dir / (file + ".enc")
                try:
                    file_metadata = self.encryptor.encrypt_file(
                        input_path=str(file_path),
                        output_path=str(output_file),
                        key_id=key_id,
                        password=password
                    )
                    
                    metadata["encrypted_files"].append({
                        "relative_path": str(rel_file_path),
                        "encrypted_path": str(output_file.relative_to(output_dir)),
                        "original_size": file_metadata.original_size,
                        "key_info_type": file_metadata.key_info.type
                    })
                    
                    stats["files_encrypted"] += 1
                    stats["bytes_encrypted"] += file_metadata.original_size
                    
                except Exception as e:
                    logger.error(f"Error encrypting {file_path}: {str(e)}")
                    stats["errors"] += 1
        
        # Write metadata
        stats["end_time"] = datetime.now()
        stats["duration_seconds"] = (stats["end_time"] - stats["start_time"]).total_seconds()
        
        metadata.update({
            "stats": stats,
            "include_patterns": include_patterns,
            "exclude_patterns": exclude_patterns,
        })
        
        with open(output_dir / "vault_encryption_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2, default=str)
        
        return stats
    
    def decrypt_vault(self,
                     encrypted_path: str,
                     output_path: Optional[str] = None,
                     password: Optional[str] = None) -> Dict[str, Any]:
        """Decrypt an encrypted Obsidian vault.
        
        Args:
            encrypted_path: Path to the encrypted vault
            output_path: Path to save the decrypted vault (defaults to encrypted_path + '_decrypted')
            password: Optional password to use for decryption
            
        Returns:
            Dictionary with decryption statistics
        """
        encrypted_dir = Path(encrypted_path)
        
        if not encrypted_dir.exists() or not encrypted_dir.is_dir():
            raise ValueError(f"Encrypted vault path does not exist or is not a directory: {encrypted_path}")
        
        if output_path is None:
            output_path = str(encrypted_dir) + "_decrypted"
        
        output_dir = Path(output_path)
        os.makedirs(output_dir, exist_ok=True)
        
        # Read metadata
        metadata_path = encrypted_dir / "vault_encryption_metadata.json"
        if not metadata_path.exists():
            raise ValueError(f"Metadata file not found: {metadata_path}")
        
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        
        stats = {
            "files_processed": 0,
            "files_decrypted": 0,
            "bytes_decrypted": 0,
            "errors": 0,
            "skipped_files": 0,
            "start_time": datetime.now(),
        }
        
        # Process encrypted files
        for encrypted_file_info in metadata.get("encrypted_files", []):
            stats["files_processed"] += 1
            
            encrypted_rel_path = encrypted_file_info["encrypted_path"]
            original_rel_path = encrypted_file_info["relative_path"]
            
            encrypted_file_path = encrypted_dir / encrypted_rel_path
            output_file_path = output_dir / original_rel_path
            
            # Create parent directories if needed
            output_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                decrypted_info = self.encryptor.decrypt_file(
                    input_path=str(encrypted_file_path),
                    output_path=str(output_file_path),
                    password=password
                )
                
                stats["files_decrypted"] += 1
                stats["bytes_decrypted"] += decrypted_info.original_size
                
            except Exception as e:
                logger.error(f"Error decrypting {encrypted_file_path}: {str(e)}")
                stats["errors"] += 1
                
        # Copy non-encrypted files
        for root, dirs, files in os.walk(encrypted_dir):
            rel_path = Path(root).relative_to(encrypted_dir)
            
            for file in files:
                if file == "vault_encryption_metadata.json" or file.endswith(".meta") or file.endswith(".enc"):
                    continue
                
                file_path = Path(root) / file
                rel_file_path = file_path.relative_to(encrypted_dir)
                output_file = output_dir / rel_file_path
                
                output_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, output_file)
                stats["skipped_files"] += 1
        
        stats["end_time"] = datetime.now()
        stats["duration_seconds"] = (stats["end_time"] - stats["start_time"]).total_seconds()
        
        return stats


class JsonLogAdapter(StorageAdapter):
    """Adapter for encrypting/decrypting JSON logs"""
    
    def __init__(self, encryptor: Encryptor):
        """Initialize the JSON log adapter.
        
        Args:
            encryptor: The encryptor to use for encryption/decryption operations
        """
        super().__init__(encryptor)
    
    def encrypt_json_file(self, 
                         input_path: str, 
                         output_path: Optional[str] = None,
                         fields_to_encrypt: Optional[List[str]] = None,
                         nested_fields: Optional[Dict[str, List[str]]] = None,
                         key_id: Optional[str] = None) -> Dict[str, Any]:
        """Encrypt specific fields in a JSON file.
        
        Args:
            input_path: Path to the input JSON file
            output_path: Path to save the encrypted JSON file (defaults to input_path + '.enc.json')
            fields_to_encrypt: List of top-level field names to encrypt
            nested_fields: Dict mapping parent fields to lists of child fields to encrypt
            key_id: Optional key ID to use for encryption
            
        Returns:
            Dictionary with encryption statistics
        """
        input_file = Path(input_path)
        
        if not input_file.exists():
            raise ValueError(f"Input file does not exist: {input_path}")
        
        if output_path is None:
            output_path = str(input_file) + ".enc.json"
        
        # Initialize fields if None
        if fields_to_encrypt is None:
            fields_to_encrypt = []
        
        if nested_fields is None:
            nested_fields = {}
        
        stats = {
            "fields_encrypted": 0,
            "start_time": datetime.now(),
        }
        
        try:
            # Read the JSON file
            with open(input_path, "r") as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, list):
                # List of records
                for record in data:
                    self._encrypt_json_object(record, fields_to_encrypt, nested_fields, key_id, stats)
            elif isinstance(data, dict):
                # Single record or complex structure
                self._encrypt_json_object(data, fields_to_encrypt, nested_fields, key_id, stats)
            else:
                raise ValueError(f"Unsupported JSON structure in {input_path}")
            
            # Write the encrypted JSON
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            
            stats["end_time"] = datetime.now()
            stats["duration_seconds"] = (stats["end_time"] - stats["start_time"]).total_seconds()
            
            return stats
        
        except Exception as e:
            logger.error(f"Error encrypting JSON file {input_path}: {str(e)}")
            raise
    
    def decrypt_json_file(self,
                         input_path: str,
                         output_path: Optional[str] = None,
                         fields_to_decrypt: Optional[List[str]] = None,
                         nested_fields: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
        """Decrypt specific fields in an encrypted JSON file.
        
        Args:
            input_path: Path to the encrypted JSON file
            output_path: Path to save the decrypted JSON file
            fields_to_decrypt: List of top-level field names to decrypt
            nested_fields: Dict mapping parent fields to lists of child fields to decrypt
            
        Returns:
            Dictionary with decryption statistics
        """
        input_file = Path(input_path)
        
        if not input_file.exists():
            raise ValueError(f"Input file does not exist: {input_path}")
        
        if output_path is None:
            if input_path.endswith(".enc.json"):
                output_path = input_path[:-9] + ".dec.json"
            else:
                output_path = str(input_file) + ".dec.json"
        
        # Initialize fields if None
        if fields_to_decrypt is None:
            fields_to_decrypt = []
        
        if nested_fields is None:
            nested_fields = {}
        
        stats = {
            "fields_decrypted": 0,
            "start_time": datetime.now(),
        }
        
        try:
            # Read the JSON file
            with open(input_path, "r") as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, list):
                # List of records
                for record in data:
                    self._decrypt_json_object(record, fields_to_decrypt, nested_fields, stats)
            elif isinstance(data, dict):
                # Single record or complex structure
                self._decrypt_json_object(data, fields_to_decrypt, nested_fields, stats)
            else:
                raise ValueError(f"Unsupported JSON structure in {input_path}")
            
            # Write the decrypted JSON
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            
            stats["end_time"] = datetime.now()
            stats["duration_seconds"] = (stats["end_time"] - stats["start_time"]).total_seconds()
            
            return stats
        
        except Exception as e:
            logger.error(f"Error decrypting JSON file {input_path}: {str(e)}")
            raise
    
    def _encrypt_json_object(self, obj: Dict, fields: List[str], nested_fields: Dict[str, List[str]], 
                           key_id: Optional[str], stats: Dict[str, Any]):
        """Encrypt fields in a JSON object.
        
        Args:
            obj: The JSON object to encrypt fields in
            fields: List of field names to encrypt
            nested_fields: Dict mapping parent fields to lists of child fields to encrypt
            key_id: Optional key ID to use for encryption
            stats: Dictionary for tracking encryption statistics
        """
        if not isinstance(obj, dict):
            return
        
        # Encrypt top-level fields
        for field in fields:
            if field in obj and obj[field] is not None:
                obj[field] = self.encryptor.encrypt_db_field(obj[field], key_id)
                stats["fields_encrypted"] += 1
        
        # Encrypt nested fields
        for parent_field, child_fields in nested_fields.items():
            if parent_field in obj and isinstance(obj[parent_field], dict):
                for child_field in child_fields:
                    if child_field in obj[parent_field] and obj[parent_field][child_field] is not None:
                        obj[parent_field][child_field] = self.encryptor.encrypt_db_field(
                            obj[parent_field][child_field], key_id
                        )
                        stats["fields_encrypted"] += 1
            elif parent_field in obj and isinstance(obj[parent_field], list):
                # Handle list of objects
                for item in obj[parent_field]:
                    if isinstance(item, dict):
                        for child_field in child_fields:
                            if child_field in item and item[child_field] is not None:
                                item[child_field] = self.encryptor.encrypt_db_field(
                                    item[child_field], key_id
                                )
                                stats["fields_encrypted"] += 1
    
    def _decrypt_json_object(self, obj: Dict, fields: List[str], nested_fields: Dict[str, List[str]], 
                           stats: Dict[str, Any]):
        """Decrypt fields in a JSON object.
        
        Args:
            obj: The JSON object to decrypt fields in
            fields: List of field names to decrypt
            nested_fields: Dict mapping parent fields to lists of child fields to decrypt
            stats: Dictionary for tracking decryption statistics
        """
        if not isinstance(obj, dict):
            return
        
        # Decrypt top-level fields
        for field in fields:
            if field in obj and obj[field] is not None:
                try:
                    obj[field] = self.encryptor.decrypt_db_field(obj[field])
                    stats["fields_decrypted"] += 1
                except (DecryptionError, ValueError, json.JSONDecodeError):
                    # Skip fields that aren't actually encrypted
                    pass
        
        # Decrypt nested fields
        for parent_field, child_fields in nested_fields.items():
            if parent_field in obj and isinstance(obj[parent_field], dict):
                for child_field in child_fields:
                    if child_field in obj[parent_field] and obj[parent_field][child_field] is not None:
                        try:
                            obj[parent_field][child_field] = self.encryptor.decrypt_db_field(
                                obj[parent_field][child_field]
                            )
                            stats["fields_decrypted"] += 1
                        except (DecryptionError, ValueError, json.JSONDecodeError):
                            # Skip fields that aren't actually encrypted
                            pass
            elif parent_field in obj and isinstance(obj[parent_field], list):
                # Handle list of objects
                for item in obj[parent_field]:
                    if isinstance(item, dict):
                        for child_field in child_fields:
                            if child_field in item and item[child_field] is not None:
                                try:
                                    item[child_field] = self.encryptor.decrypt_db_field(
                                        item[child_field]
                                    )
                                    stats["fields_decrypted"] += 1
                                except (DecryptionError, ValueError, json.JSONDecodeError):
                                    # Skip fields that aren't actually encrypted
                                    pass