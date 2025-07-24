from typing import Optional, List
from models import ShareInfo, FileInfo, ConnectionConfig, ItemType
from datetime import datetime

try:
    from smb.SMBConnection import SMBConnection
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False

class SMBConnector:
    """Handles SMB connection operations"""
    
    def __init__(self):
        self.connection: Optional[SMBConnection] = None
        self.config: Optional[ConnectionConfig] = None
    
    def connect(self, config: ConnectionConfig) -> tuple[bool, str]:
        """Establish SMB connection"""
        try:
            self.config = config
            self.connection = SMBConnection(
                config.username, 
                config.password, 
                "EnumTool", 
                config.target,
                domain=config.domain, 
                use_ntlm_v2=True
            )
            
            connected = self.connection.connect(
                config.target, 
                config.port, 
                timeout=config.timeout
            )
            
            if connected:
                return True, "Connected successfully"
            else:
                return False, "Connection failed - authentication or network issue"
                
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def disconnect(self):
        """Close SMB connection"""
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            finally:
                self.connection = None
    
    def is_connected(self) -> bool:
        """Check if connection is active"""
        return self.connection is not None
    
    def get_connection(self) -> Optional[SMBConnection]:
        """Get the active connection"""
        return self.connection

class ShareEnumerator:
    """Handles SMB share enumeration"""
    
    def __init__(self, connector: SMBConnector):
        self.connector = connector
    
    def list_shares(self) -> list[ShareInfo, str]:
        """Get list of available shares"""
        connection = self.connector.get_connection()
        if not connection:
            return [], "No active connection"
        
        try:
            shares = connection.listShares(timeout=10)
            share_list = []
            
            for share in shares:
                share_info = ShareInfo(
                    name=share.name,
                    share_type=share.type,
                    comments=share.comments,
                    is_special=share.isSpecial
                )
                share_list.append(share_info)
            
            return share_list, "Success"
            
        except Exception as e:
            return [], f"Error listing shares: {str(e)}"

class DirectoryEnumerator:
    """Handles directory enumeration within shares"""
    
    def __init__(self, connector: SMBConnector):
        self.connector = connector
        self.stop_flag = False
    
    def set_stop_flag(self, stop: bool):
        """Set the stop flag for enumeration"""
        self.stop_flag = stop
    
    def enumerate_directory(self, share_name: str, path: str = "", depth: int = 0) -> List[FileInfo]:
        """Enumerate contents of a directory"""
        connection = self.connector.get_connection()
        if not connection or self.stop_flag:
            return []
        
        results = []
        try:
            files = connection.listPath(share_name, path or "/", timeout=10)
            
            for file_info in files:
                if file_info.filename in ['.', '..']:
                    continue
                
                file_path = f"{path}/{file_info.filename}" if path else file_info.filename
                
                try:
                    modified_time = datetime.fromtimestamp(file_info.last_write_time)
                except:
                    modified_time = None
                
                item_type = ItemType.DIRECTORY if file_info.isDirectory else ItemType.FILE
                
                file_data = FileInfo(
                    share=share_name,
                    path=file_path,
                    name=file_info.filename,
                    size=file_info.file_size,
                    is_directory=file_info.isDirectory,
                    modified=modified_time,
                    depth=depth,
                    item_type=item_type
                )
                
                results.append(file_data)
                
        except Exception as e:
            # Add error entry
            error_info = FileInfo(
                share=share_name,
                path=path,
                name=f"[ERROR] {str(e)[:50]}...",
                size=0,
                is_directory=False,
                modified=None,
                depth=depth,
                item_type=ItemType.ERROR,
                error_message=str(e)
            )
            results.append(error_info)
        
        return results

class RecursiveEnumerator:
    """Handles recursive enumeration with depth control"""
    
    def __init__(self, connector: SMBConnector):
        self.connector = connector
        self.dir_enumerator = DirectoryEnumerator(connector)
        self.stop_flag = False
    
    def set_stop_flag(self, stop: bool):
        """Set stop flag for enumeration"""
        self.stop_flag = stop
        self.dir_enumerator.set_stop_flag(stop)
    
    def enumerate_recursive(self, share_name: str, max_depth: int, 
                          current_path: str = "", current_depth: int = 0) -> List[FileInfo]:
        """Recursively enumerate share contents"""
        if self.stop_flag or current_depth >= max_depth:
            return []
        
        all_results = []
        
        # Get current directory contents
        current_results = self.dir_enumerator.enumerate_directory(
            share_name, current_path, current_depth
        )
        all_results.extend(current_results)
        
        # Recurse into subdirectories
        if current_depth < max_depth - 1:
            for item in current_results:
                if self.stop_flag:
                    break
                    
                if item.is_directory and item.item_type != ItemType.ERROR:
                    try:
                        sub_results = self.enumerate_recursive(
                            share_name, max_depth, item.path, current_depth + 1
                        )
                        all_results.extend(sub_results)
                        
                    except Exception as e:
                        # Add access denied entry
                        access_denied = FileInfo(
                            share=share_name,
                            path=item.path,
                            name=f"[ACCESS DENIED] {item.name}",
                            size=0,
                            is_directory=True,
                            modified=None,
                            depth=current_depth + 1,
                            item_type=ItemType.ACCESS_DENIED,
                            error_message=str(e)
                        )
                        all_results.append(access_denied)
        
        return all_results