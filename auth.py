import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple
import logging
from database import SecureDatabaseManager
from models import User
import re

logger = logging.getLogger(__name__)

class AuthManager:
    def __init__(self, db_manager: SecureDatabaseManager):
        self.db_manager = db_manager
        self.session_tokens = {}  # In production, use Redis or database
        self.session_timeout = timedelta(hours=24)
        
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        if not email or not isinstance(email, str):
            return False
            
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def validate_name(self, name: str) -> bool:
        """Validate name format"""
        if not name or not isinstance(name, str):
            return False
            
        # Allow letters, spaces, and common name characters
        pattern = r'^[a-zA-Z\s\-\.\']{2,100}$'
        return re.match(pattern, name) is not None
    
    def register_user(self, email: str, name: str) -> Tuple[bool, str, Optional[User]]:
        """Register a new user with validation"""
        try:
            # Validate inputs
            if not self.validate_email(email):
                return False, "Invalid email format", None
                
            if not self.validate_name(name):
                return False, "Invalid name format", None
            
            # Check if user already exists
            existing_user = self.db_manager.get_user_by_email(email)
            if existing_user:
                if existing_user.is_blocked:
                    return False, "This email has been blocked", None
                return True, "User already exists", existing_user
            
            # Create new user
            user = self.db_manager.create_user(email, name)
            if user:
                return True, "User registered successfully", user
            else:
                return False, "Failed to create user", None
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False, "Registration failed due to system error", None
    
    def generate_session_token(self, user_id: int, email: str) -> str:
        """Generate a secure session token"""
        try:
            # Create a secure token
            token = secrets.token_urlsafe(64)
            
            # Store token with expiration
            expiration = datetime.now() + self.session_timeout
            self.session_tokens[token] = {
                'user_id': user_id,
                'email': email,
                'expires_at': expiration
            }
            
            # Update last login
            self.db_manager.update_user_last_login(user_id)
            
            return token
        except Exception as e:
            logger.error(f"Token generation error: {e}")
            raise
    
    def validate_session_token(self, token: str) -> Tuple[bool, Optional[dict]]:
        """Validate session token"""
        try:
            if not token or token not in self.session_tokens:
                return False, None
            
            session_data = self.session_tokens[token]
            
            # Check expiration
            if datetime.now() > session_data['expires_at']:
                # Token expired, remove it
                self.logout(token)
                return False, None
            
            # Update expiration (sliding window)
            session_data['expires_at'] = datetime.now() + self.session_timeout
            self.session_tokens[token] = session_data
            
            return True, session_data
            
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, None
    
    def logout(self, token: str) -> bool:
        """Invalidate session token"""
        try:
            if token in self.session_tokens:
                del self.session_tokens[token]
            return True
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False
    
    def cleanup_expired_tokens(self):
        """Clean up expired session tokens"""
        try:
            current_time = datetime.now()
            expired_tokens = [
                token for token, data in self.session_tokens.items()
                if data['expires_at'] < current_time
            ]
            
            for token in expired_tokens:
                del self.session_tokens[token]
                
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")
            
        except Exception as e:
            logger.error(f"Token cleanup error: {e}")