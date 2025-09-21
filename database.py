import psycopg2
from psycopg2 import sql, extras
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
import logging
from models import User, Meeting, Participant, ChatMessage, ConnectionLog
from encryption import encryption_manager
import json
import hashlib
import uuid

logger = logging.getLogger(__name__)

class SecureDatabaseManager:
    def __init__(self, dbname: str, user: str, password: str, host: str, port: str):
        self.db_config = {
            "dbname": dbname,
            "user": user,
            "password": password,
            "host": host,
            "port": port
        }
        self.connection = None
        self.connect()
        
    def connect(self):
        """Establish database connection with retry logic"""
        try:
            # Try connection with provided config
            try:
                self.connection = psycopg2.connect(**self.db_config)
            except psycopg2.OperationalError:
                # If connection fails, try without password
                config_without_password = self.db_config.copy()
                config_without_password["password"] = ""
                self.connection = psycopg2.connect(**config_without_password)
            
            self.connection.autocommit = True
            logger.info("Database connection established")
        
            # Initialize tables
            self._initialize_tables()
        
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            self.connection = None
            raise
    
    def check_connection(self) -> bool:
        """Check if database connection is active"""
        try:
            if self.connection is None or self.connection.closed:
                self.connect()
                return self.connection is not None
            return True
        except:
            return False
    
    def _initialize_tables(self):
        """Initialize database tables if they don't exist"""
        try:
            with self.connection.cursor() as cursor:

		# First drop any existing tables to ensure clean setup
                cursor.execute("DROP TABLE IF EXISTS connection_logs CASCADE")
                cursor.execute("DROP TABLE IF EXISTS chat_messages CASCADE")
                cursor.execute("DROP TABLE IF EXISTS participants CASCADE")
                cursor.execute("DROP TABLE IF EXISTS blocked_emails CASCADE")
                cursor.execute("DROP TABLE IF EXISTS meetings CASCADE")
                cursor.execute("DROP TABLE IF EXISTS users CASCADE")


                # Users table
                cursor.execute("""
                    CREATE TABLE users (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_blocked BOOLEAN DEFAULT FALSE,
                        encrypted_data BYTEA
                    )
                """)
                
                # Meetings table
                cursor.execute("""
                    CREATE TABLE meetings (
                        id SERIAL PRIMARY KEY,
                        room_id VARCHAR(255) UNIQUE NOT NULL,
                        title VARCHAR(500),
                        host_id INTEGER REFERENCES users(id),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ended_at TIMESTAMP,
                        encryption_key BYTEA,
                        encrypted_data BYTEA
                    )
                """)
                
                # Participants table
                cursor.execute("""
                    CREATE TABLE participants (
                        id SERIAL PRIMARY KEY,
                        meeting_id INTEGER REFERENCES meetings(id),
                        email VARCHAR(255) NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        is_host BOOLEAN DEFAULT FALSE,
                        invited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        joined_at TIMESTAMP,
                        left_at TIMESTAMP,
                        encrypted_data BYTEA,
                        UNIQUE(meeting_id, email)
                    )
                """)
                
                # Chat messages table
                cursor.execute("""
                    CREATE TABLE chat_messages (
                        id SERIAL PRIMARY KEY,
                        meeting_id INTEGER REFERENCES meetings(id),
                        user_id INTEGER REFERENCES users(id),
                        message TEXT,
                        is_ai BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        encrypted_data BYTEA,
			user_name VARCHAR(255)
                    )
                """)
                
                # Connection logs table
                cursor.execute("""
                    CREATE TABLE connection_logs (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        ip_address BYTEA,
                        user_agent BYTEA,
                        mac_address BYTEA,
                        connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        disconnected_at TIMESTAMP,
                        encrypted_data BYTEA
                    )
                """)
                
                # Blocked emails table
                cursor.execute("""
                    CREATE TABLE blocked_emails (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        reason TEXT,
                        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                logger.info("Database tables initialized/verified")
                
        except Exception as e:
            logger.error(f"Table initialization failed: {e}")
            raise
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        try:
            with self.connection.cursor(cursor_factory=extras.DictCursor) as cursor:
                # First check if the is_blocked column exists
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='users' AND column_name='is_blocked'
                """)
                has_is_blocked_column = cursor.fetchone() is not None
                
                if has_is_blocked_column:
                    cursor.execute(
                        "SELECT id, email, name, created_at, last_login, is_blocked FROM users WHERE email = %s",
                        (email,)
                    )
                else:
                    cursor.execute(
                        "SELECT id, email, name, created_at, last_login FROM users WHERE email = %s",
                        (email,)
                    )
                
                result = cursor.fetchone()
                if result:
                    return User(
                        id=result['id'],
                        email=result['email'],
                        name=result['name'],
                        created_at=result['created_at'],
                        last_login=result['last_login'],
                        is_blocked=result['is_blocked'] if has_is_blocked_column else False
                    )
                return None
        except Exception as e:
            logger.error(f"Error getting user by email: {e}")
            return None
    
    def create_user(self, email: str, name: str) -> Optional[User]:
        """Create a new user"""
        try:
            with self.connection.cursor(cursor_factory=extras.DictCursor) as cursor:
                # Check if is_blocked column exists
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='users' AND column_name='is_blocked'
                """)
                has_is_blocked_column = cursor.fetchone() is not None
                
                if has_is_blocked_column:
                    cursor.execute(
                        "INSERT INTO users (email, name) VALUES (%s, %s) RETURNING id, email, name, created_at, last_login, is_blocked",
                        (email, name)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO users (email, name) VALUES (%s, %s) RETURNING id, email, name, created_at, last_login",
                        (email, name)
                    )
                
                result = cursor.fetchone()
                if result:
                    return User(
                        id=result['id'],
                        email=result['email'],
                        name=result['name'],
                        created_at=result['created_at'],
                        last_login=result['last_login'],
                        is_blocked=result['is_blocked'] if has_is_blocked_column else False
                    )
                return None
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def update_user_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                    (user_id,)
                )
        except Exception as e:
            logger.error(f"Error updating last login: {e}")
    
    def create_meeting(self, room_id: str, host_id: int, title: str = None) -> Optional[int]:
        """Create a new meeting with encryption key"""
        try:
            # Generate encryption key for this meeting
            encryption_key = encryption_manager.generate_secure_key()
            key_bytes = encryption_key
            
            with self.connection.cursor() as cursor:
                # Check if encryption_key column exists
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='meetings' AND column_name='encryption_key'
                """)
                has_encryption_key_column = cursor.fetchone() is not None
                
                if has_encryption_key_column:
                    cursor.execute(
                        "INSERT INTO meetings (room_id, host_id, title, encryption_key) VALUES (%s, %s, %s, %s) RETURNING id",
                        (room_id, host_id, title, key_bytes)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO meetings (room_id, host_id, title) VALUES (%s, %s, %s) RETURNING id",
                        (room_id, host_id, title)
                    )
                
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Error creating meeting: {e}")
            return None
    
    def get_meeting_by_room_id(self, room_id: str) -> Optional[Meeting]:
        """Get meeting by room ID"""
        try:
            with self.connection.cursor(cursor_factory=extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT id, room_id, title, host_id, created_at, ended_at FROM meetings WHERE room_id = %s AND ended_at IS NULL",
                    (room_id,)
                )
                result = cursor.fetchone()
                if result:
                    return Meeting(
                        id=result['id'],
                        room_id=result['room_id'],
                        title=result['title'],
                        host_id=result['host_id'],
                        created_at=result['created_at'],
                        ended_at=result['ended_at']
                    )
                return None
        except Exception as e:
            logger.error(f"Error getting meeting: {e}")
            return None
    
    def get_meeting_encryption_key(self, meeting_id: int) -> Optional[bytes]:
        """Get encryption key for a meeting"""
        try:
            # Check if encryption_key column exists
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='meetings' AND column_name='encryption_key'
                """)
                has_encryption_key_column = cursor.fetchone() is not None
                
                if not has_encryption_key_column:
                    return None
                
                cursor.execute(
                    "SELECT encryption_key FROM meetings WHERE id = %s",
                    (meeting_id,)
                )
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting encryption key: {e}")
            return None
    
    def add_participant(self, meeting_id: int, email: str, name: str, is_host: bool = False) -> bool:
        """Add participant to meeting"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO participants (meeting_id, email, name, is_host) 
                       VALUES (%s, %s, %s, %s) 
                       ON CONFLICT (meeting_id, email) 
                       DO UPDATE SET name = EXCLUDED.name, is_host = EXCLUDED.is_host""",
                    (meeting_id, email, name, is_host)
                )
                return True
        except Exception as e:
            logger.error(f"Error adding participant: {e}")
            return False
    
    def mark_participant_joined(self, meeting_id: int, email: str) -> bool:
        """Mark participant as joined"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE participants SET joined_at = CURRENT_TIMESTAMP WHERE meeting_id = %s AND email = %s",
                    (meeting_id, email)
                )
                return True
        except Exception as e:
            logger.error(f"Error marking participant joined: {e}")
            return False
    
    def mark_participant_left(self, meeting_id: int, email: str) -> bool:
        """Mark participant as left"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE participants SET left_at = CURRENT_TIMESTAMP WHERE meeting_id = %s AND email = %s",
                    (meeting_id, email)
                )
                return True
        except Exception as e:
            logger.error(f"Error marking participant left: {e}")
            return False
    
    def validate_participant(self, meeting_id: int, email: str) -> bool:
        """Validate if participant is allowed to join meeting"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM participants WHERE meeting_id = %s AND email = %s",
                    (meeting_id, email)
                )
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error validating participant: {e}")
            return False
    
    def get_participants(self, meeting_id: int) -> List[Participant]:
        """Get all participants for a meeting"""
        try:
            with self.connection.cursor(cursor_factory=extras.DictCursor) as cursor:
                cursor.execute(
                    "SELECT id, meeting_id, email, name, is_host, invited_at, joined_at, left_at FROM participants WHERE meeting_id = %s ORDER BY invited_at",
                    (meeting_id,)
                )
                results = cursor.fetchall()
                participants = []
                for result in results:
                    participants.append(Participant(
                        id=result['id'],
                        meeting_id=result['meeting_id'],
                        email=result['email'],
                        name=result['name'],
                        is_host=result['is_host'],
                        invited_at=result['invited_at'],
                        joined_at=result['joined_at'],
                        left_at=result['left_at']
                    ))
                return participants
        except Exception as e:
            logger.error(f"Error getting participants: {e}")
            return []
    
    def add_chat_message(self, meeting_id: int, user_id: int, message: str, is_ai: bool = False, 
                        encryption_key: bytes = None, user_name: str = None) -> bool:
        """Add encrypted chat message"""
        try:
            # Encrypt the message if key is provided
            encrypted_data = None
            if encryption_key:
                encrypted_result = encryption_manager.encrypt(message, encryption_key)
                if encrypted_result:
                    ciphertext, iv, tag = encrypted_result
                    # Store encrypted components
                    encrypted_data = iv + tag + ciphertext
            
            with self.connection.cursor() as cursor:
                # Check if encrypted_data column exists
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='chat_messages' AND column_name='encrypted_data'
                """)
                has_encrypted_data_column = cursor.fetchone() is not None
                
                if has_encrypted_data_column and encrypted_data:
                    cursor.execute(
                        "INSERT INTO chat_messages (meeting_id, user_id, message, is_ai, encrypted_data) VALUES (%s, %s, %s, %s, %s)",
                        (meeting_id, user_id, message if not encryption_key else '', is_ai, encrypted_data)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO chat_messages (meeting_id, user_id, message, is_ai) VALUES (%s, %s, %s, %s)",
                        (meeting_id, user_id, message, is_ai)
                    )
                return True
        except Exception as e:
            logger.error(f"Error adding chat message: {e}")
            return False
    
    def get_chat_messages(self, meeting_id: int, limit: int = 50, encryption_key: bytes = None, 
                         ai_only: bool = False) -> List[ChatMessage]:
        """Get chat messages (decrypt if key provided)"""
        try:
            with self.connection.cursor(cursor_factory=extras.DictCursor) as cursor:
                if ai_only:
                    cursor.execute(
                        "SELECT cm.id, cm.meeting_id, cm.user_id, cm.message, cm.is_ai, cm.created_at, cm.encrypted_data, u.name as user_name FROM chat_messages cm LEFT JOIN users u ON cm.user_id = u.id WHERE cm.meeting_id = %s AND cm.is_ai = TRUE ORDER BY cm.created_at DESC LIMIT %s",
                        (meeting_id, limit)
                    )
                else:
                    cursor.execute(
                        "SELECT cm.id, cm.meeting_id, cm.user_id, cm.message, cm.is_ai, cm.created_at, cm.encrypted_data, u.name as user_name FROM chat_messages cm LEFT JOIN users u ON cm.user_id = u.id WHERE cm.meeting_id = %s ORDER BY cm.created_at DESC LIMIT %s",
                        (meeting_id, limit)
                    )
                
                results = cursor.fetchall()
                messages = []
                
                for result in results:
                    message_text = result['message']
                    
                    # Decrypt if encrypted data exists and key is provided
                    if result['encrypted_data'] and encryption_key:
                        try:
                            encrypted_data = result['encrypted_data']
                            iv = encrypted_data[:12]
                            tag = encrypted_data[12:28]
                            ciphertext = encrypted_data[28:]
                            
                            decrypted = encryption_manager.decrypt(ciphertext, encryption_key, iv, tag)
                            if decrypted:
                                message_text = decrypted
                        except Exception as e:
                            logger.error(f"Error decrypting message: {e}")
                            message_text = "[Encrypted message - decryption failed]"
                    
                    messages.append(ChatMessage(
                        id=result['id'],
                        meeting_id=result['meeting_id'],
                        user_id=result['user_id'],
                        user_name=result['user_name'] or "Unknown",
                        message=message_text,
                        is_ai=result['is_ai'],
                        created_at=result['created_at']
                    ))
                
                return messages
        except Exception as e:
            logger.error(f"Error getting chat messages: {e}")
            return []
    
    def log_connection(self, user_id: int, ip_address: str, user_agent: str, mac_address: str) -> Optional[int]:
        """Log user connection with encrypted data"""
        try:
            # Check if encrypted_data column exists
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='connection_logs' AND column_name='encrypted_data'
                """)
                has_encrypted_data_column = cursor.fetchone() is not None
                
                if not has_encrypted_data_column:
                    # Insert without encryption
                    cursor.execute(
                        """INSERT INTO connection_logs (user_id, ip_address, user_agent, mac_address) 
                           VALUES (%s, %s, %s, %s) RETURNING id""",
                        (user_id, ip_address.encode() if ip_address else None, 
                         user_agent.encode() if user_agent else None, 
                         mac_address.encode() if mac_address else None)
                    )
                    result = cursor.fetchone()
                    return result[0] if result else None
                
                # Encrypt sensitive data
                encryption_key = encryption_manager.generate_secure_key()
                
                encrypted_ip = None
                encrypted_agent = None
                encrypted_mac = None
                
                if ip_address:
                    encrypted_result = encryption_manager.encrypt(ip_address, encryption_key)
                    if encrypted_result:
                        ciphertext, iv, tag = encrypted_result
                        encrypted_ip = iv + tag + ciphertext
                
                if user_agent:
                    encrypted_result = encryption_manager.encrypt(user_agent, encryption_key)
                    if encrypted_result:
                        ciphertext, iv, tag = encrypted_result
                        encrypted_agent = iv + tag + ciphertext
                
                if mac_address:
                    encrypted_result = encryption_manager.encrypt(mac_address, encryption_key)
                    if encrypted_result:
                        ciphertext, iv, tag = encrypted_result
                        encrypted_mac = iv + tag + ciphertext
                
                cursor.execute(
                    """INSERT INTO connection_logs (user_id, ip_address, user_agent, mac_address, encrypted_data) 
                       VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                    (user_id, encrypted_ip, encrypted_agent, encrypted_mac, encryption_key)
                )
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.error(f"Error logging connection: {e}")
            return None
    
    def log_disconnection(self, connection_id: int) -> bool:
        """Log user disconnection"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE connection_logs SET disconnected_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (connection_id,)
                )
                return True
        except Exception as e:
            logger.error(f"Error logging disconnection: {e}")
            return False
    
    def end_meeting(self, meeting_id: int) -> bool:
        """End a meeting"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE meetings SET ended_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (meeting_id,)
                )
                return True
        except Exception as e:
            logger.error(f"Error ending meeting: {e}")
            return False
    
    def is_email_blocked(self, email: str) -> bool:
        """Check if email is blocked"""
        try:
            # Check if blocked_emails table exists
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'blocked_emails'
                    )
                """)
                table_exists = cursor.fetchone()[0]
                
                if not table_exists:
                    return False
                
                cursor.execute(
                    "SELECT 1 FROM blocked_emails WHERE email = %s",
                    (email,)
                )
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking blocked email: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
            logger.info("Database connection closed")