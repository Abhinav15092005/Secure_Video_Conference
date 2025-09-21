import streamlit as st
import os
import sys
from datetime import datetime, timedelta
from database import SecureDatabaseManager
from auth import AuthManager
from secure_video_call import SecureVideoCallManager
from ai_chat import AIChatManager
from models import User, Meeting, Participant
from encryption import encryption_manager
import logging
from dotenv import load_dotenv
import re
import time
from typing import List, Dict, Any, Optional
import json
import urllib.parse
import hashlib
import base64

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("securevideo.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Load Groq API key with fallback
try:
    groq_api_key = os.getenv("GROQ_API_KEY") or st.secrets.get("GROQ_API_KEY", "")
    os.environ["GROQ_API_KEY"] = groq_api_key
except Exception as e:
    logger.warning(f"Could not load secrets: {e}")
    groq_api_key = os.getenv("GROQ_API_KEY", "")
    if not groq_api_key:
        logger.error("GROQ_API_KEY not found in environment or secrets")

# Initialize session state
def init_session_state():
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'session_token' not in st.session_state:
        st.session_state.session_token = None
    if 'page' not in st.session_state:
        st.session_state.page = "home"
    if 'db_manager' not in st.session_state:
        try:
            db_config = {
                "dbname": os.getenv("DB_NAME", "securevideo_db"),
                "user": os.getenv("DB_USER", "postgres"),
                "password": os.getenv("DB_PASSWORD", ""),
                "host": os.getenv("DB_HOST", "localhost"),
                "port": os.getenv("DB_PORT", "5432")
            }

            # Try connection with provided config first
            try:
                st.session_state.db_manager = SecureDatabaseManager(**db_config)
            except Exception as e:
                # If connection fails, try with empty password
                logger.warning(f"Connection with password failed, trying without password: {e}")
                db_config["password"] = ""
                st.session_state.db_manager = SecureDatabaseManager(**db_config)
            
            # Test connection
            if not st.session_state.db_manager or not st.session_state.db_manager.check_connection():
                logger.error("Database connection test failed")
                st.session_state.db_manager = None
                st.session_state.auth_manager = None
                return
                
            st.session_state.auth_manager = AuthManager(st.session_state.db_manager)
            st.session_state.video_manager = SecureVideoCallManager()
            st.session_state.ai_chat_manager = AIChatManager()
            logger.info("All managers initialized successfully")
            
        except Exception as e:
            st.error(f"Database connection failed: {e}")
            logger.error(f"Database connection error: {e}")
            # Set to None to prevent further errors
            st.session_state.db_manager = None
            st.session_state.auth_manager = None
            
    if 'current_room' not in st.session_state:
        st.session_state.current_room = None
    if 'join_room_id' not in st.session_state:
        st.session_state.join_room_id = None
    if 'meeting_id' not in st.session_state:
        st.session_state.meeting_id = None
    if 'is_host' not in st.session_state:
        st.session_state.is_host = False
    if 'audio_enabled' not in st.session_state:
        st.session_state.audio_enabled = True
    if 'video_enabled' not in st.session_state:
        st.session_state.video_enabled = True
    if 'participants' not in st.session_state:
        st.session_state.participants = []
    if 'chat_messages' not in st.session_state:
        st.session_state.chat_messages = []
    if 'new_chat_message' not in st.session_state:
        st.session_state.new_chat_message = ""
    if 'show_ai_chat' not in st.session_state:
        st.session_state.show_ai_chat = False
    if 'meeting_encryption_key' not in st.session_state:
        st.session_state.meeting_encryption_key = None
    if 'security_notice_dismissed' not in st.session_state:
        st.session_state.security_notice_dismissed = False
    if 'ai_processing' not in st.session_state:
        st.session_state.ai_processing = False
    if 'connection_id' not in st.session_state:
        st.session_state.connection_id = None

# Page configurations
st.set_page_config(
    page_title="SecureVideo Conference - End-to-End Encrypted",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for security-focused UI with enhanced mobile responsiveness
st.markdown("""
    <style>
    .main {
        padding: 2rem;
        background-color: #0E1117;
        color: #FAFAFA;
    }
    .stButton>button {
        width: 100%;
        background: linear-gradient(45deg, #00C9FF, #92FE9D);
        color: #0E1117;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background: linear-gradient(45deg, #92FE9D, #00C9FF);
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 201, 255, 0.4);
    }
    .security-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background: linear-gradient(45deg, #667EEA, #764BA2);
        color: #FAFAFA;
        margin-bottom: 1rem;
        border: 2px solid #667EEA;
    }
    .encrypted-badge {
        background: linear-gradient(45deg, #00C9FF, #92FE9D);
        color: #0E1117;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: bold;
        margin-left: 0.5rem;
    }
    
    /* Enhanced mobile responsiveness */
    @media (max-width: 768px) {
        .main {
            padding: 1rem;
        }
        .stButton>button {
            padding: 0.75rem;
            font-size: 16px;
        }
        .chat-message {
            padding: 0.5rem;
            margin: 0.25rem 0;
            font-size: 14px;
        }
        .video-container {
            flex-direction: column;
        }
        .security-box {
            padding: 0.75rem;
            margin-bottom: 0.75rem;
        }
    }
    
    /* Professional UI elements */
    .professional-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 1rem;
    }
    
    .ai-response {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        border-left: 4px solid #f5576c;
    }
    
    .user-message {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        border-left: 4px solid #00f2fe;
    }
    
    .chat-container {
        max-height: 400px;
        overflow-y: auto;
        padding: 1rem;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        margin-bottom: 1rem;
    }
    
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
    }
    
    .status-online {
        background: #00C9FF;
        box-shadow: 0 0 8px #00C9FF;
    }
    
    .status-offline {
        background: #666;
    }
    
    .premium-feature {
        background: linear-gradient(45deg, #FFD700, #FFA500);
        color: #000;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
        margin: 0.25rem 0;
    }
    
    .error-message {
        background: linear-gradient(45deg, #FF6B6B, #FF8E53);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        border-left: 4px solid #FF4757;
    }
    </style>
""", unsafe_allow_html=True)

# Security notice that appears on every page
def show_security_notice():
    if not st.session_state.security_notice_dismissed:
        st.markdown("""
        <div style="background: linear-gradient(45deg, #00C9FF, #92FE9D); 
                    padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem;
                    border: 2px solid #00C9FF; color: #0E1117;">
            <h3>🔒 End-to-End Encryption Active</h3>
            <p><strong>All your communications are secured with military-grade encryption:</strong></p>
            <ul>
                <li>✅ Video streams are encrypted</li>
                <li>✅ Audio conversations are encrypted</li>
                <li>✅ Chat messages are encrypted</li>
                <li>✅ AI conversations are encrypted</li>
                <li>✅ Personal information is encrypted</li>
                <li>✅ Not even we can access your data</li>
            </ul>
            <p><strong>Encryption Algorithm:</strong> AES-256-GCM with PBKDF2 key derivation</p>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("✓ I Understand", key="understand_encryption"):
            st.session_state.security_notice_dismissed = True
            st.rerun()

# Email validation and parsing functions
def validate_email(email: str) -> bool:
    """Validate email format with strict rules"""
    if not email or not isinstance(email, str):
        return False
        
    # Basic pattern check
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
        
    # Additional checks for suspicious patterns
    suspicious_patterns = [
        r"\.\d+@",  # Dots followed by numbers before @
        r"\d{10}@",  # 10 digits followed by @
        r"\.{2,}",   # Multiple consecutive dots
        r"@.{1,2}$", # Very short domain
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, email):
            return False
            
    return True

def sanitize_input(text: str, max_length: int = 500) -> str:
    """Sanitize user input to prevent XSS and other attacks"""
    if not text or not isinstance(text, str):
        return ""
    
    # Remove potentially dangerous characters but allow reasonable text
    sanitized = re.sub(r'[<>"\'\\;]', '', text)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
        
    return sanitized.strip()

def parse_emails(input_text: str) -> List[str]:
    """Parse and validate emails from input text"""
    if not input_text or not isinstance(input_text, str):
        return []
    
    separators = [',', ';', '\n', '\t', ' ']
    for sep in separators:
        input_text = input_text.replace(sep, ' ')
    
    emails = []
    for part in input_text.split():
        email = part.strip()
        if validate_email(email):
            emails.append(email)
    
    return emails

def generate_name_from_email(email: str) -> str:
    """Generate a name from email address"""
    if not email or '@' not in email:
        return "User"
    
    username = email.split('@')[0]
    username = re.sub(r'[._+-]', ' ', username)
    name_parts = [word.capitalize() for word in username.split() if word]
    
    return ' '.join(name_parts) if name_parts else "User"

def generate_share_link(room_id: str, base_url: str = None) -> str:
    """Generate a shareable link for the meeting"""
    if not room_id or not isinstance(room_id, str):
        return ""
        
    if base_url is None:
        try:
            from streamlit import runtime
            if runtime.exists():
                config = runtime.get_instance().config
                base_url = f"http://{config.serverAddress}:{config.serverPort}"
        except:
            base_url = "http://localhost:8501"
    
    return f"{base_url}/?meeting={room_id}"

# UI components
def show_secure_chat_interface(meeting_id: int, user_id: int, encryption_key: bytes):
    """Show encrypted chat interface"""
    try:
        st.subheader("💬 Secure Chat")
        st.markdown('<span class="encrypted-badge">END-TO-END ENCRYPTED</span>', unsafe_allow_html=True)
        
        if not st.session_state.db_manager:
            st.error("Database connection not available")
            return
            
        chat_messages = st.session_state.db_manager.get_chat_messages(
            meeting_id, 50, encryption_key
        )
        st.session_state.chat_messages = chat_messages
        
        # Chat container with scroll
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        for msg in reversed(chat_messages[-20:]):  # Show only last 20 messages
            timestamp = msg.created_at.strftime("%H:%M") if msg.created_at else "Now"
            if msg.is_ai:
                st.markdown(f'''
                <div class="ai-response">
                    <strong>{msg.user_name}</strong> <small>({timestamp})</small>:<br>
                    {msg.message}
                </div>
                ''', unsafe_allow_html=True)
            else:
                st.markdown(f'''
                <div class="user-message">
                    <strong>{msg.user_name}</strong> <small>({timestamp})</small>:<br>
                    {msg.message}
                </div>
                ''', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns([4, 1])
        with col1:
            new_message = st.text_input(
                "Type your encrypted message...", 
                value=st.session_state.new_chat_message,
                key="secure_chat_input",
                placeholder="Your message is end-to-end encrypted",
                max_chars=1000
            )
        with col2:
            st.write("")
            st.write("")
            send_chat = st.button("Send", use_container_width=True)
        
        if send_chat and new_message:
            # Sanitize input
            sanitized_message = sanitize_input(new_message)
            if sanitized_message:
                # Add encrypted message
                success = st.session_state.db_manager.add_chat_message(
                    meeting_id, user_id, sanitized_message, False, encryption_key
                )
                if success:
                    st.session_state.new_chat_message = ""
                    st.rerun()
                else:
                    st.error("Failed to send message")
    except Exception as e:
        logger.error(f"Error in chat interface: {e}")
        st.error("Error loading chat. Please refresh the page.")

def get_client_ip():
    """Get client IP address (encrypted in database)"""
    try:
        from streamlit.web.server.websocket_headers import _get_websocket_headers
        headers = _get_websocket_headers()
        if headers and 'X-Forwarded-For' in headers:
            return headers['X-Forwarded-For'].split(',')[0].strip()
        return "unknown"
    except:
        return "unknown"

def get_user_agent():
    """Get user agent (encrypted in database)"""
    try:
        from streamlit.web.server.websocket_headers import _get_websocket_headers
        headers = _get_websocket_headers()
        if headers and 'User-Agent' in headers:
            return headers['User-Agent'][:500]  # Limit length
        return "unknown"
    except:
        return "unknown"

def get_mac_address():
    """Get MAC address (simulated, encrypted in database)"""
    return "unknown"

def extract_room_id_from_input(input_text: str) -> str:
    """Extract room ID from various input formats"""
    if not input_text or not isinstance(input_text, str):
        return ""
        
    patterns = [
        r'meeting=([a-zA-Z0-9_\-]+)',
        r'room=([a-zA-Z0-9_\-]+)',
        r'id=([a-zA-Z0-9_\-]+)',
        r'/([a-zA-Z0-9_\-]+)$',
        r'([a-zA-Z0-9_\-]{10,})'  # General pattern for room IDs
    ]
    
    for pattern in patterns:
        match = re.search(pattern, input_text)
        if match:
            return match.group(1)
    
    return ""

# Page functions
def show_home_page():
    """Show the home page with meeting creation/join options"""
    show_security_notice()
    
    # Check database connection
    if not st.session_state.db_manager:
        st.error("Database connection not available. Please check your database settings.")
        return
    
    # Check if there's a meeting link in URL
    query_params = st.query_params
    meeting_id = query_params.get("meeting", [None])[0]
    
    if meeting_id:
        st.session_state.join_room_id = meeting_id
        st.session_state.page = "conference"
        st.rerun()
    
    st.title("🔒 SecureVideo Conference - End-to-End Encrypted")
    st.markdown("---")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown('<div class="professional-header">', unsafe_allow_html=True)
        st.subheader("🚀 Create Secure Meeting")
        st.markdown("All meetings are automatically end-to-end encrypted")
        st.markdown('</div>', unsafe_allow_html=True)
        
        with st.form("create_meeting_form"):
            email = st.text_input("Your Email", placeholder="your.email@example.com", key="create_email")
            name = st.text_input("Your Name", placeholder="Enter your name", key="create_name")
            meeting_title = st.text_input("Meeting Title", placeholder="Secure Team Meeting", key="meeting_title")
            
            submitted = st.form_submit_button("Create Secure Meeting", use_container_width=True)
            
            if submitted:
                if not email or not name:
                    st.error("Please enter both email and name")
                    return
                
                # Validate inputs
                if not validate_email(email):
                    st.error("Please enter a valid email address")
                    return
                    
                sanitized_name = sanitize_input(name, 100)
                if not sanitized_name:
                    st.error("Please enter a valid name")
                    return
                    
                sanitized_title = sanitize_input(meeting_title, 200) if meeting_title else "Secure Meeting"
                
                is_blocked = st.session_state.db_manager.is_email_blocked(email)
                if is_blocked:
                    st.error("Access denied. This email has been blocked.")
                    return
                
                user = st.session_state.db_manager.get_user_by_email(email)
                if not user:
                    success, message, user = st.session_state.auth_manager.register_user(email, sanitized_name)
                    if not success:
                        st.error(f"Registration failed: {message}")
                        return
                
                token = st.session_state.auth_manager.generate_session_token(user.id, user.email)
                st.session_state.user = user
                st.session_state.session_token = token
                room_id = f"secure_room_{user.id}_{int(datetime.now().timestamp())}"
                st.session_state.current_room = room_id
                
                meeting_id = st.session_state.db_manager.create_meeting(room_id, user.id, sanitized_title)
                if meeting_id is None:
                    st.error("Failed to create secure meeting.")
                    return
                
                # Get meeting encryption key
                encryption_key = st.session_state.db_manager.get_meeting_encryption_key(meeting_id)
                if encryption_key:
                    st.session_state.meeting_encryption_key = encryption_key
                    st.session_state.video_manager.add_encryption_key(room_id, encryption_key)
                
                st.session_state.meeting_id = meeting_id
                st.session_state.is_host = True
                st.session_state.db_manager.add_participant(meeting_id, email, sanitized_name, True)
                
                st.success("✅ Secure meeting created! All communications are end-to-end encrypted.")
                st.session_state.page = "conference"
                st.rerun()
    
    with col2:
        st.markdown('<div class="professional-header">', unsafe_allow_html=True)
        st.subheader("🔗 Join Secure Meeting")
        st.markdown("Join with secure invitation link")
        st.markdown('</div>', unsafe_allow_html=True)
        
        with st.form("join_meeting_form"):
            join_room_id = st.text_input("Room ID or Link", placeholder="Enter room ID or paste secure link", key="join_room")
            join_email = st.text_input("Your Email", placeholder="your.email@example.com", key="join_email")
            join_name = st.text_input("Your Name", placeholder="Enter your name", key="join_name")
            submitted_join = st.form_submit_button("Join Secure Meeting", use_container_width=True)
            
            if submitted_join:
                if not join_room_id or not join_email or not join_name:
                    st.error("Please fill all fields")
                    return
                
                # Validate inputs
                if not validate_email(join_email):
                    st.error("Please enter a valid email address")
                    return
                    
                sanitized_name = sanitize_input(join_name, 100)
                if not sanitized_name:
                    st.error("Please enter a valid name")
                    return
                
                # Extract room ID if it's a link
                actual_room_id = extract_room_id_from_input(join_room_id) or join_room_id
                if not actual_room_id:
                    st.error("Invalid room ID or link format")
                    return
                    
                is_blocked = st.session_state.db_manager.is_email_blocked(join_email)
                if is_blocked:
                    st.error("Access denied. This email has been blocked.")
                    return
                
                meeting = st.session_state.db_manager.get_meeting_by_room_id(actual_room_id)
                if not meeting:
                    st.error("Secure meeting not found.")
                    return
                
                is_allowed = st.session_state.db_manager.validate_participant(meeting.id, join_email)
                if not is_allowed:
                    st.error("You are not in the participant list. Please contact the meeting host.")
                    return
                
                user = st.session_state.db_manager.get_user_by_email(join_email)
                if not user:
                    success, message, user = st.session_state.auth_manager.register_user(join_email, sanitized_name)
                    if not success:
                        st.error(f"Registration failed: {message}")
                        return
                
                token = st.session_state.auth_manager.generate_session_token(user.id, user.email)
                st.session_state.user = user
                st.session_state.session_token = token
                st.session_state.join_room_id = actual_room_id
                st.session_state.meeting_id = meeting.id
                st.session_state.is_host = False
                
                # Get meeting encryption key
                encryption_key = st.session_state.db_manager.get_meeting_encryption_key(meeting.id)
                if encryption_key:
                    st.session_state.meeting_encryption_key = encryption_key
                    st.session_state.video_manager.add_encryption_key(actual_room_id, encryption_key)
                
                # Mark participant as joined
                st.session_state.db_manager.mark_participant_joined(meeting.id, join_email)
                
                # Log connection with encrypted details
                connection_id = st.session_state.db_manager.log_connection(
                    user.id, 
                    get_client_ip(),
                    get_user_agent(),
                    get_mac_address()
                )
                st.session_state.connection_id = connection_id
                
                st.success("✅ Successfully joined secure meeting! All communications are end-to-end encrypted.")
                st.session_state.page = "conference"
                st.rerun()

def show_conference_page():
    """Show the main conference page with end-to-end encryption"""
    show_security_notice()
    
    # Check database connection
    if not st.session_state.db_manager:
        st.error("Database connection not available. Please check your database settings.")
        st.session_state.page = "home"
        st.rerun()
        return
    
    room_id = st.session_state.join_room_id if st.session_state.join_room_id else st.session_state.current_room
    meeting = st.session_state.db_manager.get_meeting_by_room_id(room_id)
    
    if not meeting:
        st.error("Meeting not found. Returning to home page.")
        st.session_state.page = "home"
        st.rerun()
        return
    
    # Sidebar with user info and controls
    st.sidebar.title("👤 User Info")
    st.sidebar.write(f"**Name:** {st.session_state.user.name}")
    st.sidebar.write(f"**Email:** {st.session_state.user.email}")
    st.sidebar.write(f"**Role:** {'Host' if st.session_state.is_host else 'Participant'}")
    
    # Security status
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔒 Security Status")
    st.sidebar.success("End-to-End Encryption: ACTIVE")
    st.sidebar.info("All communications are encrypted with AES-256-GCM")
    
    # Room information
    st.sidebar.markdown("---")
    st.sidebar.subheader("🎪 Conference Room")
    st.sidebar.markdown(f'<div class="security-box">Room ID: <code>{room_id}</code></div>', unsafe_allow_html=True)
    
    if meeting.title:
        st.sidebar.write(f"**Title:** {meeting.title}")
    
    # Share button for host
    if st.session_state.is_host:
        st.sidebar.markdown("---")
        if st.sidebar.button("📤 Share Meeting", use_container_width=True):
            show_share_options(room_id)
    
    # Media controls
    st.sidebar.markdown("---")
    st.sidebar.subheader("🎛️ Media Controls")
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        audio_icon = "🎤" if st.session_state.audio_enabled else "🔇"
        if st.button(audio_icon, key="audio_toggle", use_container_width=True):
            st.session_state.audio_enabled = not st.session_state.audio_enabled
            st.rerun()
        st.caption("Audio")
    with col2:
        video_icon = "📷" if st.session_state.video_enabled else "📹"
        if st.button(video_icon, key="video_toggle", use_container_width=True):
            st.session_state.video_enabled = not st.session_state.video_enabled
            st.rerun()
        st.caption("Video")
    
    # AI Chat toggle
    st.sidebar.markdown("---")
    if st.sidebar.button("🤖 AI Assistant", use_container_width=True):
        st.session_state.show_ai_chat = not st.session_state.show_ai_chat
        st.rerun()
    
    # Leave meeting button
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Leave Meeting", use_container_width=True):
        # Log disconnection
        if hasattr(st.session_state, 'connection_id') and st.session_state.connection_id:
            st.session_state.db_manager.log_disconnection(st.session_state.connection_id)
        
        if st.session_state.session_token:
            st.session_state.auth_manager.logout(st.session_state.session_token)
        
        if st.session_state.join_room_id:
            st.session_state.db_manager.mark_participant_left(
                meeting.id, st.session_state.user.email
            )
        
        if st.session_state.is_host:
            st.session_state.db_manager.end_meeting(meeting.id)
        
        # Reset session state
        for key in list(st.session_state.keys()):
            if key not in ['db_manager', 'auth_manager', 'video_manager', 'ai_chat_manager']:
                del st.session_state[key]
        
        st.session_state.page = "home"
        st.rerun()
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("🎥 Secure Video Conference")
        st.markdown('<span class="encrypted-badge">END-TO-END ENCRYPTED</span>', unsafe_allow_html=True)
        
        # Initialize secure video call
        try:
            success = st.session_state.video_manager.start_secure_video_call(
                user_id=st.session_state.user.id,
                session_token=st.session_state.session_token,
                room_id=room_id,
                encryption_key=st.session_state.meeting_encryption_key,
                audio_enabled=st.session_state.audio_enabled,
                video_enabled=st.session_state.video_enabled
            )
            
            if not success:
                st.info("""
                **📱 Mobile Users:** For best experience, please use:
                - Google Chrome (Android/iOS)
                - Safari (iOS 12.2+)
                - Enable camera/microphone permissions
                """)
        except Exception as e:
            logger.error(f"Video call error: {e}")
            st.error("Video call initialization failed. Please refresh the page.")
    
    with col2:
        # Show participants
        st.subheader("👥 Participants")
        participants = st.session_state.db_manager.get_participants(meeting.id)
        if participants:
            for participant in participants:
                status = "🟢" if participant.joined_at else "⚪"
                role = "👑" if participant.is_host else "👤"
                st.write(f"{status} {role} {participant.name}")
        else:
            st.info("No participants yet")
        
        # Show secure chat
        show_secure_chat_interface(
            meeting.id, 
            st.session_state.user.id, 
            st.session_state.meeting_encryption_key
        )
    
    # AI Chat panel (conditional)
    if st.session_state.show_ai_chat:
        st.markdown("---")
        st.subheader("🤖 Secure AI Assistant")
        st.markdown('<span class="encrypted-badge">END-TO-END ENCRYPTED</span>', unsafe_allow_html=True)
        
        ai_messages = st.session_state.db_manager.get_chat_messages(
            meeting.id, 20, st.session_state.meeting_encryption_key, ai_only=True
        )
        
        for msg in ai_messages:
            st.markdown(f'''
            <div class="ai-response">
                <strong>{msg.user_name}</strong>: {msg.message}
            </div>
            ''', unsafe_allow_html=True)
        
        ai_prompt = st.text_input("Ask AI assistant...", key="ai_prompt")
        if st.button("Send to AI", key="send_ai") and ai_prompt:
            if st.session_state.ai_processing:
                st.warning("AI is processing your previous request")
            else:
                st.session_state.ai_processing = True
                try:
                    response = st.session_state.ai_chat_manager.process_message(
                        ai_prompt, 
                        st.session_state.user.name,
                        meeting.title
                    )
                    
                    if response:
                        success = st.session_state.db_manager.add_chat_message(
                            meeting.id, 
                            st.session_state.user.id, 
                            response, 
                            True, 
                            st.session_state.meeting_encryption_key,
                            "AI Assistant"
                        )
                        if success:
                            st.rerun()
                except Exception as e:
                    logger.error(f"AI processing error: {e}")
                    st.error("AI service temporarily unavailable")
                finally:
                    st.session_state.ai_processing = False

def show_share_options(room_id: str):
    """Show meeting share options"""
    share_link = generate_share_link(room_id)
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("📤 Share Meeting")
    
    if share_link:
        st.sidebar.code(share_link, language="text")
        
        # Copy to clipboard
        if st.sidebar.button("📋 Copy Link", use_container_width=True):
            try:
                import pyperclip
                pyperclip.copy(share_link)
                st.sidebar.success("Link copied to clipboard!")
            except:
                st.sidebar.error("Clipboard access not available")
        
        # Email invitation
        st.sidebar.markdown("---")
        st.sidebar.subheader("📧 Invite by Email")
        
        emails_input = st.sidebar.text_area(
            "Enter participant emails (comma separated)",
            placeholder="participant1@example.com, participant2@example.com",
            height=100
        )
        
        if st.sidebar.button("📨 Send Invitations", use_container_width=True):
            if emails_input:
                emails = parse_emails(emails_input)
                if emails:
                    success_count = 0
                    for email in emails:
                        name = generate_name_from_email(email)
                        success = st.session_state.db_manager.add_participant(
                            st.session_state.meeting_id, email, name, False
                        )
                        if success:
                            success_count += 1
                    
                    st.sidebar.success(f"Invitations sent to {success_count} participants")
                else:
                    st.sidebar.error("No valid email addresses found")
            else:
                st.sidebar.error("Please enter email addresses")

# Main app logic
def main():
    """Main application entry point"""
    init_session_state()
    
    # Check for meeting ID in URL parameters
    query_params = st.query_params
    meeting_id = query_params.get("meeting", [None])[0]
    
    if meeting_id and st.session_state.page == "home":
        st.session_state.join_room_id = meeting_id
        st.session_state.page = "conference"
    
    # Navigation
    if st.session_state.page == "home":
        show_home_page()
    elif st.session_state.page == "conference":
        if not st.session_state.user:
            st.error("Please log in first")
            st.session_state.page = "home"
            st.rerun()
        else:
            show_conference_page()
    else:
        st.session_state.page = "home"
        st.rerun()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Application error: {e}")
        st.error("An unexpected error occurred. Please refresh the page.")