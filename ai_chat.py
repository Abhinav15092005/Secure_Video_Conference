import os
import logging
from typing import Optional
import requests
import json
import time
from datetime import datetime

logger = logging.getLogger(__name__)

class AIChatManager:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama3-70b-8192"  # Using LLaMA 3 70B model
        self.max_retries = 3
        self.timeout = 30
        
    def process_message(self, message: str, user_name: str, meeting_title: str = None) -> Optional[str]:
        """Process user message through AI with enhanced security context"""
        try:
            if not self.api_key:
                logger.error("Groq API key not configured")
                return "AI service is currently unavailable. Please try again later."
            
            # Enhanced system prompt with security focus
            system_prompt = f"""You are a secure AI assistant for a video conferencing platform. 
            User: {user_name}
            Meeting: {meeting_title or 'Secure Meeting'}
            
            GUIDELINES:
            1. Provide helpful, professional responses
            2. Focus on meeting productivity, collaboration, and security
            3. Keep responses concise but informative
            4. Do not share sensitive information
            5. Maintain privacy and confidentiality
            6. Be positive and encouraging
            
            SECURITY CONTEXT:
            - All communications are end-to-end encrypted
            - User privacy is paramount
            - No data is stored or used for training
            
            CAPABILITIES:
            - Meeting facilitation
            - Technical support
            - Idea brainstorming
            - Document review assistance
            - Time management
            - Security best practices
            
            Always respond in a way that respects user privacy and maintains the highest security standards."""

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message}
                ],
                "temperature": 0.7,
                "max_tokens": 1000,
                "top_p": 1,
                "stream": False
            }

            for attempt in range(self.max_retries):
                try:
                    response = requests.post(
                        self.base_url,
                        headers=headers,
                        json=payload,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        return data['choices'][0]['message']['content'].strip()
                    
                    elif response.status_code == 429:
                        # Rate limited, wait and retry
                        wait_time = 2 ** attempt
                        logger.warning(f"Rate limited, waiting {wait_time}s (attempt {attempt + 1})")
                        time.sleep(wait_time)
                        continue
                    
                    else:
                        logger.error(f"API error {response.status_code}: {response.text}")
                        break
                        
                except requests.exceptions.Timeout:
                    logger.warning(f"Request timeout (attempt {attempt + 1})")
                    if attempt == self.max_retries - 1:
                        raise
                    time.sleep(1)
                    
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request failed: {e}")
                    break

            return "I apologize, but I'm experiencing technical difficulties. Please try again in a moment."

        except Exception as e:
            logger.error(f"AI processing error: {e}")
            return "I'm currently unable to process your request. Please try again later."

    def generate_meeting_summary(self, chat_history: list) -> Optional[str]:
        """Generate meeting summary from chat history"""
        try:
            if not self.api_key:
                return None

            system_prompt = """You are a meeting summarization assistant. Analyze the chat history and generate a concise, professional meeting summary. 
            Include key points, decisions made, and action items. Keep it structured and easy to read."""

            # Prepare chat history for the AI
            formatted_history = "\n".join([
                f"{msg['user']} ({msg['timestamp']}): {msg['message']}" 
                for msg in chat_history[-50:]  # Last 50 messages
            ])

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Please summarize this meeting chat history:\n\n{formatted_history}"}
                ],
                "temperature": 0.3,
                "max_tokens": 500,
                "top_p": 1,
                "stream": False
            }

            response = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data['choices'][0]['message']['content'].strip()
            
            return None

        except Exception as e:
            logger.error(f"Meeting summary error: {e}")
            return None