from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

@dataclass
class User:
    id: int
    email: str
    name: str
    created_at: datetime
    last_login: Optional[datetime] = None
    is_blocked: bool = False

@dataclass
class Meeting:
    id: int
    room_id: str
    host_id: int
    created_at: datetime
    title: Optional[str] = None
    ended_at: Optional[datetime] = None

@dataclass
class Participant:
    id: int
    meeting_id: int
    email: str
    name: str
    is_host: bool = False
    invited_at: Optional[datetime] = None
    joined_at: Optional[datetime] = None
    left_at: Optional[datetime] = None

@dataclass
class ChatMessage:
    id: int
    meeting_id: int
    user_id: int
    message: str
    is_ai: bool = False
    created_at: Optional[datetime] = None
    user_name: Optional[str] = None

@dataclass
class ConnectionLog:
    id: int
    user_id: int
    connected_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    mac_address: Optional[str] = None
    disconnected_at: Optional[datetime] = None