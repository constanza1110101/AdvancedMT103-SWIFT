#!/usr/bin/env python3
"""
Advanced MT103 Parser - Cybersecurity Tool
A comprehensive tool for parsing, analyzing, validating, and securing SWIFT MT103 payment messages.
Author: Constanza
Version: 2.0.0
"""

import re
import json
import csv
import xml.etree.ElementTree as ET
import hashlib
import base64
import datetime
import logging
import os
import sys
import argparse
from typing import Dict, List, Optional, Tuple, Any, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.syntax import Syntax
from rich.logging import RichHandler
from rich.traceback import install as install_rich_traceback
from concurrent.futures import ThreadPoolExecutor
import sqlite3

# Set up enhanced logging with Rich
install_rich_traceback()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("mt103_parser")

console = Console()

class MT103Parser:
    """
    Advanced parser for SWIFT MT103 messages with security features.
    Provides comprehensive parsing, validation, security analysis, and cryptographic protection.
    """
    
    # Enhanced regex pattern to capture more field details
    MESSAGE_REGEX = re.compile(
        r"^({1:(?P<basic_header>[^}]+)})?({2:(?P<application_header>(I|O)[^}]+)})?({3:(?P<user_header>.*)})?({4:\s*(?P<text>.+?)\s*-})?({5:(?P<trailer>.+)})?$",
        re.DOTALL,
    )
    
    # Field definitions for validation and parsing
    FIELD_DEFINITIONS = {
        ":20:": {"name": "Transaction Reference", "required": True, "max_length": 16},
        ":23B:": {"name": "Bank Operation Code", "required": True, "valid_values": ["CRED", "SPAY", "SPRI", "SSTD"]},
        ":32A:": {"name": "Value Date/Currency/Amount", "required": True, "pattern": r"^\d{6}[A-Z]{3}[\d,]+$"},
        ":33B:": {"name": "Currency/Original Amount", "required": False},
        ":50K:": {"name": "Ordering Customer", "required": True},
        ":52A:": {"name": "Ordering Institution", "required": False},
        ":56A:": {"name": "Intermediary Institution", "required": False},
        ":57A:": {"name": "Account With Institution", "required": False},
        ":59:": {"name": "Beneficiary Customer", "required": True},
        ":70:": {"name": "Remittance Information", "required": False},
        ":71A:": {"name": "Details of Charges", "required": True, "valid_values": ["OUR", "SHA", "BEN"]},
        ":72:": {"name": "Sender to Receiver Information", "required": False}
    }
    
    # High-risk countries and entities for security screening
    HIGH_RISK_JURISDICTIONS = [
        "NORTH KOREA", "IRAN", "SYRIA", "CUBA", "VENEZUELA", 
        "MYANMAR", "BELARUS", "RUSSIA", "CRIMEA", "AFGHANISTAN",
        "YEMEN", "SOMALIA"
    ]
    
    # Suspicious keywords that might indicate fraud or money laundering
    SUSPICIOUS_KEYWORDS = [
        "URGENT", "CONFIDENTIAL", "SECRET", "IMMEDIATE", "OFFSHORE",
        "SHELL", "QUICK", "UNDISCLOSED", "ANONYMOUS", "NOMINEE",
        "TAX HAVEN", "UNREGISTERED", "UNREPORTED", "UNTRACEABLE"
    ]
    
    def __init__(self, message: str, encryption_key: Optional[bytes] = None):
        """
        Initialize the MT103 parser with a message and optional encryption key.
        
        Args:
            message: The raw MT103 message string
            encryption_key: Optional encryption key for secure operations
        """
        self.raw = message.strip()
        self.basic_header = None
        self.application_header = None
        self.user_header = None
        self.text = None
        self.trailer = None
        self.parsed_fields = {}
        self.validation_errors = []
        self.security_issues = []
        self._boolean = False
        self.encryption_key = encryption_key
        self.hash_signature = None
        self.processing_timestamp = datetime.datetime.now()
        self._populate_by_parsing()
        self._calculate_hash()

    def _populate_by_parsing(self) -> None:
        """Parse the raw message into structured components and fields."""
        if not self.raw:
            logger.error("Empty message provided")
            return
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Parsing MT103 message...", total=4)
            m = self.MESSAGE_REGEX.match(self.raw)
            self._boolean = bool(m)
            if not m:
                logger.error("Message format does not match MT103 pattern")
                return
            
            self.basic_header = m.group("basic_header")
            progress.update(task, advance=1)
            self.application_header = m.group("application_header")
            self.trailer = m.group("trailer")
            progress.update(task, advance=1)
            self.user_header = m.group("user_header")
            self.text = m.group("text")
            progress.update(task, advance=1)
            
            # Parse individual fields from the text block
            if self.text:
                self._parse_fields()
            
            # Validate the parsed message against field definitions
            self._validate_fields()
            progress.update(task, advance=1)

    def _parse_fields(self) -> None:
        """Parse individual fields from the text block using regex patterns."""
        if not self.text:
            return
            
        # Find all field markers in the format :nn: or :nnX:
        field_pattern = r':(\d{2}[A-Z]?):'
        field_positions = [(m.group(), m.start()) for m in re.finditer(field_pattern, self.text)]
        
        # Extract field contents based on positions
        for i, (field_tag, position) in enumerate(field_positions):
            start_pos = position + len(field_tag)
            end_pos = field_positions[i+1][1] if i+1 < len(field_positions) else len(self.text)
            field_content = self.text[start_pos:end_pos].strip()
            self.parsed_fields[field_tag] = field_content

    def _validate_fields(self) -> None:
        """Validate parsed fields against defined rules."""
        for field_tag, definition in self.FIELD_DEFINITIONS.items():
            # Check required fields
            if definition.get("required", False) and field_tag not in self.parsed_fields:
                self.validation_errors.append(f"Required field {field_tag} ({definition['name']}) is missing")
                continue
                
            if field_tag not in self.parsed_fields:
                continue
                
            value = self.parsed_fields[field_tag]
            
            # Check max length if specified
            if "max_length" in definition and len(value) > definition["max_length"]:
                self.validation_errors.append(
                    f"Field {field_tag} exceeds maximum length of {definition['max_length']}"
                )
            
            # Check valid values if specified
            if "valid_values" in definition and value not in definition["valid_values"]:
                self.validation_errors.append(
                    f"Field {field_tag} contains invalid value '{value}'. Valid values: {', '.join(definition['valid_values'])}"
                )
            
            # Check pattern if specified
            if "pattern" in definition and not re.match(definition["pattern"], value):
                self.validation_errors.append(
                    f"Field {field_tag} value '{value}' does not match required pattern"
                )

    def _calculate_hash(self) -> None:
        """Calculate a cryptographic hash of the message for integrity verification."""
        if self.raw:
            hash_obj = hashlib.sha256(self.raw.encode())
            self.hash_signature = hash_obj.hexdigest()

    def display(self) -> None:
        """Display parsed message with rich formatting."""
        console.print(Panel("[bold cyan]MT103 Parsed Message[/bold cyan]", style="cyan"))
        
        # Display basic headers
        headers_table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        headers_table.add_column("Section", style="cyan")
        headers_table.add_column("Value", style="yellow")
        
        headers_table.add_row("Basic Header", self.basic_header or "[red]Not Available[/red]")
        headers_table.add_row("Application Header", self.application_header or "[red]Not Available[/red]")
        headers_table.add_row("User Header", self.user_header or "[red]Not Available[/red]")
        headers_table.add_row("Trailer", self.trailer or "[red]Not Available[/red]")
        
        console.print(headers_table)
        
        # Display parsed fields
        if self.parsed_fields:
            fields_table = Table(show_header=True, header_style="bold magenta", show_lines=True)
            fields_table.add_column("Field", style="cyan")
            fields_table.add_column("Name", style="green")
            fields_table.add_column("Value", style="yellow")
            
            for field_tag, value in self.parsed_fields.items():
                field_name = self.FIELD_DEFINITIONS.get(field_tag, {}).get("name", "Unknown Field")
                fields_table.add_row(field_tag, field_name, value)
            
            console.print(fields_table)
        
        # Display validation errors if any
        if self.validation_errors:
            console.print(Panel("[bold red]Validation Errors[/bold red]", style="red"))
            for error in self.validation_errors:
                console.print(f"[red]• {error}[/red]")
        
        # Display security issues if any
        if self.security_issues:
            console.print(Panel("[bold red]Security Issues[/bold red]", style="red"))
            for issue in self.security_issues:
                console.print(f"[red]• {issue}[/red]")
        
        # Display hash signature
        if self.hash_signature:
            console.print(f"[dim]Message Hash: {self.hash_signature}[/dim]")

    def encrypt_message(self, password: Optional[str] = None) -> Optional[Dict[str, str]]:
        """
        Encrypt the message using Fernet symmetric encryption.
        
        Args:
            password: Optional password to derive encryption key
            
        Returns:
            Dict containing encrypted data and metadata, or None if encryption fails
        """
        if not self.raw:
            logger.error("No message to encrypt")
            return None
            
        if not password and not self.encryption_key:
            logger.error("No encryption key or password provided")
            return None
            
        try:
            if password:
                # Derive key from password
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            else:
                key = self.encryption_key
                salt = None
                
            f = Fernet(key)
            encrypted_data = f.encrypt(self.raw.encode())
            
            result = {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "salt": base64.b64encode(salt).decode() if salt else None,
                "timestamp": self.processing_timestamp.isoformat(),
                "hash": self.hash_signature
            }
            
            return result
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            return None

    def decrypt_message(self, encrypted_data: str, password: Optional[str] = None, salt: Optional[str] = None) -> Optional[str]:
        """
        Decrypt an encrypted message.
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            password: Optional password to derive decryption key
            salt: Salt used for key derivation if password is provided
            
        Returns:
            Decrypted message as string, or None if decryption fails
        """
        try:
            if password and salt:
                # Recreate key from password and salt
                decoded_salt = base64.b64decode(salt)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=decoded_salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            elif self.encryption_key:
                key = self.encryption_key
            else:
                logger.error("No decryption key available")
                return None
                
            f = Fernet(key)
            decrypted_data = f.decrypt(base64.b64decode(encrypted_data))
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return None

    def export_json(self, filename: str = "mt103.json") -> str:
        """
        Export parsed message to JSON format.
        
        Args:
            filename: Output filename
            
        Returns:
            Path to the exported file
        """
        data = {
            "message_hash": self.hash_signature,
            "timestamp": self.processing_timestamp.isoformat(),
            "headers": {
                "basic_header": self.basic_header,
                "application_header": self.application_header,
                "user_header": self.user_header,
                "trailer": self.trailer
            },
            "fields": self.parsed_fields,
            "validation": {
                "is_valid": len(self.validation_errors) == 0,
                "errors": self.validation_errors
            },
            "security": {
                "issues": self.security_issues,
                "risk_level": self._calculate_risk_level()
            }
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        console.print(f"[green]Exported to {filename}[/green]")
        return filename

    def export_csv(self, filename: str = "mt103.csv") -> str:
        """
        Export parsed message to CSV format.
        
        Args:
            filename: Output filename
            
        Returns:
            Path to the exported file
        """
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Section", "Field", "Value"])
            
            # Write headers
            writer.writerow(["Header", "Basic Header", self.basic_header or "Not Available"])
            writer.writerow(["Header", "Application Header", self.application_header or "Not Available"])
            writer.writerow(["Header", "User Header", self.user_header or "Not Available"])
            writer.writerow(["Header", "Trailer", self.trailer or "Not Available"])
            
            # Write fields
            for field_tag, value in self.parsed_fields.items():
                field_name = self.FIELD_DEFINITIONS.get(field_tag, {}).get("name", "Unknown Field")
                writer.writerow(["Field", f"{field_tag} ({field_name})", value])
                
            # Write validation status
            writer.writerow(["Validation", "Is Valid", str(len(self.validation_errors) == 0)])
            for i, error in enumerate(self.validation_errors):
                writer.writerow(["Validation", f"Error {i+1}", error])
                
            # Write security issues
            writer.writerow(["Security", "Risk Level", self._calculate_risk_level()])
            for i, issue in enumerate(self.security_issues):
                writer.writerow(["Security", f"Issue {i+1}", issue])
                
            # Write hash
            writer.writerow(["Security", "Message Hash", self.hash_signature or "Not Available"])
            writer.writerow(["Metadata", "Processing Timestamp", self.processing_timestamp.isoformat()])
            
        console.print(f"[green]Exported to {filename} (CSV)[/green]")
        return filename

    def export_xml(self, filename: str = "mt103.xml") -> str:
        """
        Export parsed message to XML format.
        
        Args:
            filename: Output filename
            
        Returns:
            Path to the exported file
        """
        root = ET.Element("MT103")
        
        # Add metadata
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "ProcessingTimestamp").text = self.processing_timestamp.isoformat()
        ET.SubElement(metadata, "MessageHash").text = self.hash_signature or "Not Available"
        
        # Add headers
        headers = ET.SubElement(root, "Headers")
        ET.SubElement(headers, "BasicHeader").text = self.basic_header or "Not Available"
        ET.SubElement(headers, "ApplicationHeader").text = self.application_header or "Not Available"
        ET.SubElement(headers, "UserHeader").text = self.user_header or "Not Available"
        ET.SubElement(headers, "Trailer").text = self.trailer or "Not Available"
        
        # Add fields
        fields = ET.SubElement(root, "Fields")
        for field_tag, value in self.parsed_fields.items():
            field = ET.SubElement(fields, "Field")
            ET.SubElement(field, "Tag").text = field_tag
            field_name = self.FIELD_DEFINITIONS.get(field_tag, {}).get("name", "Unknown Field")
            ET.SubElement(field, "Name").text = field_name
            ET.SubElement(field, "Value").text = value
            
        # Add validation
        validation = ET.SubElement(root, "Validation")
        ET.SubElement(validation, "IsValid").text = str(len(self.validation_errors) == 0)
        errors = ET.SubElement(validation, "Errors")
        for error in self.validation_errors:
            ET.SubElement(errors, "Error").text = error
            
        # Add security
        security = ET.SubElement(root, "Security")
        ET.SubElement(security, "RiskLevel").text = self._calculate_risk_level()
        issues = ET.SubElement(security, "Issues")
        for issue in self.security_issues:
            ET.SubElement(issues, "Issue").text = issue
            
        # Write to file
        tree = ET.ElementTree(root)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        console.print(f"[green]Exported to {filename} (XML)[/green]")
        return filename

    def search_field(self, field: str) -> Union[str, bool]:
        """
        Search for a field in the message.
        
        Args:
            field: Field tag or content to search for
            
        Returns:
            Field value if found as a parsed field, True if found in raw message, False otherwise
        """
        if field in self.parsed_fields:
            console.print(f"[green]Found field '{field}' with value: {self.parsed_fields[field]}[/green]")
            return self.parsed_fields[field]
        elif field in self.raw:
            console.print(f"[yellow]Found '{field}' in the raw message but not as a parsed field[/yellow]")
            return True
        else:
            console.print(f"[red]'{field}' not found in the message[/red]")
            return False

    def summary(self) -> Dict[str, str]:
        """
        Generate a transaction summary with key fields.
        
        Returns:
            Dictionary of summary fields and values
        """
        summary_fields = {
            "Transaction Reference": self.parsed_fields.get(":20:", "Not Available"),
            "Value Date/Currency/Amount": self.parsed_fields.get(":32A:", "Not Available"),
            "Ordering Customer": self.parsed_fields.get(":50K:", "Not Available"),
            "Beneficiary Customer": self.parsed_fields.get(":59:", "Not Available"),
            "Details of Charges": self.parsed_fields.get(":71A:", "Not Available"),
            "Remittance Information": self.parsed_fields.get(":70:", "Not Available")
        }
        
        # Extract and format date, currency and amount from field 32A if available
        if ":32A:" in self.parsed_fields:
            value_date_currency_amount = self.parsed_fields[":32A:"]
            if re.match(r"^\d{6}[A-Z]{3}[\d,]+$", value_date_currency_amount):
                date_str = value_date_currency_amount[:6]
                currency = value_date_currency_amount[6:9]
                amount = value_date_currency_amount[9:]
                
                # Format date as YYYY-MM-DD
                try:
                    formatted_date = f"20{date_str[:2]}-{date_str[2:4]}-{date_str[4:6]}"
                    summary_fields["Value Date"] = formatted_date
                    summary_fields["Currency"] = currency
                    summary_fields["Amount"] = amount
                    # Remove the combined field
                    summary_fields.pop("Value Date/Currency/Amount")
                except:
                    pass
        
        table = Table(title="MT103 Transaction Summary", show_lines=True)
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="bold yellow")
        
        for field, value in summary_fields.items():
            table.add_row(field, value if value else "[red]Not Available[/red]")
        
        # Add validation status
        is_valid = len(self.validation_errors) == 0
        table.add_row("Validation Status", 
                     "[green]Valid[/green]" if is_valid else "[red]Invalid - See full details[/red]")
        
        # Add security risk level
        risk_level = self._calculate_risk_level()
        risk_color = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "red bold"}
        table.add_row("Security Risk Level", 
                     f"[{risk_color.get(risk_level, 'yellow')}]{risk_level}[/{risk_color.get(risk_level, 'yellow')}]")
        
        console.print(table)
        return summary_fields

    def analyze_security(self) -> List[str]:
        """
        Analyze message for security concerns.
        
        Returns:
            List of identified security issues
        """
        self.security_issues = []
        
        # Check for potentially suspicious content
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in self.raw.upper():
                self.security_issues.append(f"Message contains potentially suspicious keyword: {keyword}")
        
        # Check for unusual amounts
        if ":32A:" in self.parsed_fields:
            value_date_currency_amount = self.parsed_fields[":32A:"]
            if re.match(r"^\d{6}[A-Z]{3}[\d,]+$", value_date_currency_amount):
                amount_str = value_date_currency_amount[9:].replace(",", "")
                try:
                    amount = float(amount_str)
                    if amount > 1000000:  # Example threshold
                        self.security_issues.append(f"High-value transaction detected: {amount}")
                except:
                    pass
        
        # Check for known high-risk countries
        for country in self.HIGH_RISK_JURISDICTIONS:
            if country in self.raw.upper():
                self.security_issues.append(f"Message references high-risk jurisdiction: {country}")
        
        # Check for structural anomalies
        if len(self.validation_errors) > 3:
            self.security_issues.append(f"Message has multiple validation errors ({len(self.validation_errors)}), possible fraud attempt")
        
        # Check for inconsistencies between fields
        if ":50K:" in self.parsed_fields and ":59:" in self.parsed_fields:
            if self.parsed_fields[":50K:"].upper() == self.parsed_fields[":59:"].upper():
                self.security_issues.append("Ordering customer and beneficiary are identical, possible money laundering")
        
        # Display security analysis
        console.print(Panel("[bold]Security Analysis[/bold]", style="yellow"))
        if not self.security_issues:
            console.print("[green]No security concerns identified[/green]")
        else:
            console.print(f"[red]Security concerns identified ({len(self.security_issues)}):[/red]")
            for issue in self.security_issues:
                console.print(f"[red]• {issue}[/red]")
        
        # Display risk level
        risk_level = self._calculate_risk_level()
        risk_color = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "red bold"}
        console.print(f"[{risk_color.get(risk_level, 'yellow')}]Risk Level: {risk_level}[/{risk_color.get(risk_level, 'yellow')}]")
        
        return self.security_issues

    def _calculate_risk_level(self) -> str:
        """
        Calculate the security risk level based on identified issues.
        
        Returns:
            Risk level as string: "Low", "Medium", "High", or "Critical"
        """
        if not self.security_issues:
            return "Low"
        
        # Count issues by severity
        high_severity_count = 0
        medium_severity_count = 0
        
        for issue in self.security_issues:
            if "high-risk jurisdiction" in issue.lower() or "possible fraud" in issue.lower():
                high_severity_count += 1
            else:
                medium_severity_count += 1
        
        # Determine overall risk level
        if high_severity_count >= 2 or len(self.security_issues) >= 5:
            return "Critical"
        elif high_severity_count >= 1 or len(self.security_issues) >= 3:
            return "High"
        elif medium_severity_count >= 1:
            return "Medium"
        else:
            return "Low"

    def save_to_database(self, db_path: str = "mt103_messages.db") -> bool:
        """
        Save parsed message to SQLite database.
        
        Args:
            db_path: Path to SQLite database file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create database connection
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_signature TEXT UNIQUE,
                processing_timestamp TEXT,
                basic_header TEXT,
                application_header TEXT,
                user_header TEXT,
                trailer TEXT,
                raw_message TEXT,
                is_valid INTEGER,
                risk_level TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_hash TEXT,
                field_tag TEXT,
                field_name TEXT,
                field_value TEXT,
                FOREIGN KEY (message_hash) REFERENCES messages (hash_signature)
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS validation_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_hash TEXT,
                error_message TEXT,
                FOREIGN KEY (message_hash) REFERENCES messages (hash_signature)
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_hash TEXT,
                issue_description TEXT,
                FOREIGN KEY (message_hash) REFERENCES messages (hash_signature)
            )
            ''')
            
            # Insert message data
            cursor.execute('''
            INSERT OR REPLACE INTO messages 
            (hash_signature, processing_timestamp, basic_header, application_header, 
             user_header, trailer, raw_message, is_valid, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.hash_signature,
                self.processing_timestamp.isoformat(),
                self.basic_header,
                self.application_header,
                self.user_header,
                self.trailer,
                self.raw,
                1 if len(self.validation_errors) == 0 else 0,
                self._calculate_risk_level()
            ))
            
            # Insert field data
            for field_tag, value in self.parsed_fields.items():
                field_name = self.FIELD_DEFINITIONS.get(field_tag, {}).get("name", "Unknown Field")
                cursor.execute('''
                INSERT INTO fields (message_hash, field_tag, field_name, field_value)
                VALUES (?, ?, ?, ?)
                ''', (self.hash_signature, field_tag, field_name, value))
            
            # Insert validation errors
            for error in self.validation_errors:
                cursor.execute('''
                INSERT INTO validation_errors (message_hash, error_message)
                VALUES (?, ?)
                ''', (self.hash_signature, error))
            
            # Insert security issues
            for issue in self.security_issues:
                cursor.execute('''
                INSERT INTO security_issues (message_hash, issue_description)
                VALUES (?, ?)
                ''', (self.hash_signature, issue))
            
            # Commit changes and close connection
            conn.commit()
            conn.close()
            
            console.print(f"[green]Message saved to database: {db_path}[/green]")
            return True
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            return False

    @staticmethod
    def load_from_database(hash_signature: str, db_path: str = "mt103_messages.db") -> Optional['MT103Parser']:
        """
        Load a message from the database by its hash signature.
        
        Args:
            hash_signature: SHA-256 hash signature of the message
            db_path: Path to SQLite database file
            
        Returns:
            MT103Parser instance if found, None otherwise
        """
        try:
            # Create database connection
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Retrieve message data
            cursor.execute('''
            SELECT * FROM messages WHERE hash_signature = ?
            ''', (hash_signature,))
            message_data = cursor.fetchone()
            
            if not message_data:
                console.print(f"[red]No message found with hash: {hash_signature}[/red]")
                conn.close()
                return None
            
            # Create MT103 instance from raw message
            mt103 = MT103Parser(message_data
