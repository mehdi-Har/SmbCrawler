from datetime import datetime
from typing import Optional
import tkinter as tk
from tkinter import scrolledtext

class FileUtils:
    """File and formatting utilities"""
    
    @staticmethod
    def format_size(size: int) -> str:
        """Format file size in human readable format"""
        if size == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    @staticmethod
    def format_datetime(dt: Optional[datetime]) -> str:
        """Format datetime for display"""
        if dt is None:
            return "-"
        return dt.strftime("%Y-%m-%d %H:%M")

class Logger:
    """Logging utility"""
    
    def __init__(self, log_widget: scrolledtext.ScrolledText):
        self.log_widget = log_widget
    
    def log(self, message: str, level: str = "INFO"):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {level}: {message}\n"
        
        self.log_widget.insert(tk.END, formatted_message)
        self.log_widget.see(tk.END)
        self.log_widget.master.update_idletasks()
