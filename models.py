from dataclasses import dataclass
from typing import Optional
from enum import Enum
from datetime import datetime

class ItemType(Enum):
    FILE = "File"
    DIRECTORY = "Directory"
    ERROR = "Error"
    ACCESS_DENIED = "Access Denied"

@dataclass
class ShareInfo:
    name: str
    share_type: int
    comments: str
    is_special: bool = False

@dataclass
class FileInfo:
    share: str
    path: str
    name: str
    size: int
    is_directory: bool
    modified: Optional[datetime]
    depth: int
    item_type: ItemType
    error_message: Optional[str] = None

@dataclass
class ConnectionConfig:
    target: str
    username: str
    password: str
    domain: str = ""
    port: int = 445
    timeout: int = 10