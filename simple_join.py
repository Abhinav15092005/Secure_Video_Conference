import streamlit as st
import requests
import json
from datetime import datetime
import re

def validate_email(email):
    """Simple email validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def show_simple_join_page():
    """Simple join page for non-technical users"""
    
    st.markdown("""
    <style>
    .main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        padding: 2rem;
    }
    .join-container {
        background: white;
        border-radius: 15px;
        padding: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        max-width: 500px;
        margin: 0 auto;
    }
    .stButton>button {
        background: linear-gradient(45deg, #FF6B6B, #FF8E53);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 12px 24px;
        font-size: 16px;
        font-weight: bold;
        width: 100%;
        margin-top: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<div class="join-container">', unsafe_allow_html=True)
    
    st.title("🎥 Join Meeting")
    st.write("Enter the meeting link you received:")
    
    # Get meeting link from URL parameters or input
    query_params = st.experimental_get_query_params()
    meeting_link = query_params.get("meeting", [""])[0]
    
    if not meeting_link:
        meeting_link = st.text_input("Meeting Link:", placeholder="https://your-domain.com/join?meeting=ROOM_ID")
    
    if meeting_link:
        # Extract room ID from link
        room_id = extract_room_id(meeting_link)
        
        if room_id:
            st.success(f"Meeting found: {room_id}")
            
            with st.form("join_form"):
                name = st.text_input("Your Name:", placeholder="Enter your full name")
                email = st.text_input("Your Email:", placeholder="your.email@example.com")
                
                if st.form_submit_button("Join Meeting"):
                    if not name or not email:
                        st.error("Please enter both name and email")
                    elif not validate_email(email):
                        st.error("Please enter a valid email address")
                    else:
                        # Join the meeting
                        join_meeting(room_id, name, email)
        else:
            st.error("Invalid meeting link. Please check the link and try again.")
    
    st.markdown('</div>', unsafe_allow_html=True)

def extract_room_id(link):
    """Extract room ID from various link formats"""
    # Handle different link formats
    patterns = [
        r'meeting=([a-zA-Z0-9_\-]+)',
        r'room=([a-zA-Z0-9_\-]+)',
        r'id=([a-zA-Z0-9_\-]+)',
        r'/([a-zA-Z0-9_\-]+)$'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, link)
        if match:
            return match.group(1)
    
    return None

def join_meeting(room_id, name, email):
    """Join a meeting with the given credentials"""
    try:
        # This would connect to your backend in a real implementation
        # For now, we'll simulate the process
        
        st.session_state.join_room_id = room_id
        st.session_state.user_name = name
        st.session_state.user_email = email
        
        st.success("✅ Successfully joined meeting!")
        st.info("You will be redirected to the meeting room shortly...")
        
        # Simulate redirect (in real app, this would set session state)
        st.write(f"Meeting Room: {room_id}")
        st.write(f"Welcome, {name}!")
        
        # Show meeting instructions
        st.markdown("""
        ### Meeting Instructions:
        1. **Allow camera/microphone** permissions when prompted
        2. **Join audio** by clicking the microphone icon
        3. **Start video** by clicking the camera icon
        4. **Use chat** to communicate with others
        5. **Enjoy the meeting!** 🎉
        """)
        
    except Exception as e:
        st.error(f"Error joining meeting: {str(e)}")

if __name__ == "__main__":
    show_simple_join_page()