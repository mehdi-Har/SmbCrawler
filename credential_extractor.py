import re
import xml.etree.ElementTree as ET
from pathlib import Path

def parse_connection_string(conn_str):
    """Parse database connection strings for credentials"""
    credentials = []
    
    # Common connection string patterns
    patterns = [
        (r'User\s*Id\s*=\s*([^;]+)', 'username'),
        (r'Username\s*=\s*([^;]+)', 'username'),
        (r'Uid\s*=\s*([^;]+)', 'username'),
        (r'Password\s*=\s*([^;]+)', 'password'),
        (r'Pwd\s*=\s*([^;]+)', 'password'),
    ]
    
    found_creds = {}
    for pattern, field_type in patterns:
        match = re.search(pattern, conn_str, re.IGNORECASE)
        if match:
            found_creds[field_type] = match.group(1).strip('"\'')
    
    if 'username' in found_creds and 'password' in found_creds:
        credentials.append({
            'type': 'credential_pair',
            'username': found_creds['username'],
            'password': found_creds['password'],
            'source': 'connection_string'
        })
    
    return credentials

def is_key_file(file_path):
    """Check if file is a key/certificate file that shouldn't be parsed for credentials"""
    key_extensions = ['.key', '.pem', '.p12', '.pfx', '.crt', '.cer', '.der']
    file_ext = Path(file_path).suffix.lower()
    return file_ext in key_extensions or 'id_rsa' in Path(file_path).name.lower()

def extract_credentials_from_txt(file_path, file_content):
    """Extract credentials from text files"""
    credentials = []
    
    # Common credential patterns
    patterns = [
        # Direct username:password format (like admin:secret123)
        (r'^([a-zA-Z0-9_\-\.]+)\s*[:=]\s*([^\s\n\r]+)$', 'direct_colon_format'),
        # user=value, pass=value format (same line)
        (r'(?:user(?:name)?|login|account)\s*[:=]\s*([^\s\n\r]+).*?(?:pass(?:word)?|pwd)\s*[:=]\s*([^\s\n\r]+)', 'user_pass_pair'),
        # password first, then username (same line)
        (r'(?:pass(?:word)?|pwd)\s*[:=]\s*([^\s\n\r]+).*?(?:user(?:name)?|login|account)\s*[:=]\s*([^\s\n\r]+)', 'pass_user_pair'),
        # Simple key-value pairs - improved regex
        (r'(?i)\b(username|user|login|account|email)\s*[:=]\s*([^\s\n\r]+)', 'username_only'),
        (r'(?i)\b(password|pass|pwd|secret|key)\s*[:=]\s*([^\s\n\r]+)', 'password_only'),
    ]
    
    lines = file_content.split('\n')
    
    # First pass: collect individual credentials and immediate pairs
    single_creds = {}
    line_numbers = {}
    individual_fields = []  # Store individual fields temporarily
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
            
        for pattern, pattern_type in patterns:
            matches = re.findall(pattern, line, re.IGNORECASE)
            if matches:
                for match in matches:
                    if pattern_type == 'direct_colon_format':
                        # Only use this for actual username:password pairs (not "username : value")
                        username, password = match
                        if len(password) > 2 and username.lower() not in ['username', 'user', 'login', 'account', 'password', 'pass', 'pwd']:
                            credentials.append({
                                'type': 'credential_pair',
                                'username': username,
                                'password': password,
                                'line': i + 1,
                                'context': line
                            })
                    elif pattern_type == 'user_pass_pair':
                        username, password = match
                        credentials.append({
                            'type': 'credential_pair',
                            'username': username,
                            'password': password,
                            'line': i + 1,
                            'context': line
                        })
                    elif pattern_type == 'pass_user_pair':
                        password, username = match
                        credentials.append({
                            'type': 'credential_pair',
                            'username': username,
                            'password': password,
                            'line': i + 1,
                            'context': line
                        })
                    elif pattern_type in ['username_only', 'password_only']:
                        field_type, value = match
                        field_key = field_type.lower()
                        
                        # Store for potential pairing
                        if field_key in ['username', 'user', 'login', 'account', 'email']:
                            single_creds['username'] = value
                            line_numbers['username'] = i + 1
                        elif field_key in ['password', 'pass', 'pwd', 'secret', 'key']:
                            single_creds['password'] = value
                            line_numbers['password'] = i + 1
                        
                        # Store individual field temporarily
                        individual_fields.append({
                            'type': 'single_field',
                            'field': field_key,
                            'value': value,
                            'line': i + 1,
                            'context': line
                        })
    
    # Second pass: try to pair username and password from separate lines
    paired = False
    if 'username' in single_creds and 'password' in single_creds:
        # Check if they're close to each other (within 5 lines)
        username_line = line_numbers['username']
        password_line = line_numbers['password']
        
        if abs(username_line - password_line) <= 5:
            # Create a credential pair from separate lines
            credentials.append({
                'type': 'credential_pair',
                'username': single_creds['username'],
                'password': single_creds['password'],
                'line': f"{username_line},{password_line}",
                'context': f"username from line {username_line}, password from line {password_line}",
                'source': 'multi_line_pairing'
            })
            paired = True
    
    # Only add individual fields if they couldn't be paired
    if not paired:
        credentials.extend(individual_fields)
    
    return credentials

def extract_credentials_from_xml(file_path, file_content):
    """Extract credentials from XML files"""
    credentials = []
    
    try:
        root = ET.fromstring(file_content)
        
        # Common XML credential patterns
        credential_elements = [
            './/username', './/user', './/login', './/account',
            './/password', './/pass', './/pwd', './/secret',
            './/connectionString', './/connectionStrings'
        ]
        
        # Look for credential elements
        found_creds = {}
        for pattern in credential_elements:
            elements = root.findall(pattern)
            for elem in elements:
                if elem.text and elem.text.strip():
                    tag_name = elem.tag.lower()
                    if any(x in tag_name for x in ['user', 'login', 'account']):
                        found_creds['username'] = elem.text.strip()
                    elif any(x in tag_name for x in ['pass', 'pwd', 'secret']):
                        found_creds['password'] = elem.text.strip()
                    elif 'connection' in tag_name:
                        # Parse connection strings
                        conn_creds = parse_connection_string(elem.text)
                        credentials.extend(conn_creds)
        
        if 'username' in found_creds and 'password' in found_creds:
            credentials.append({
                'type': 'credential_pair',
                'username': found_creds['username'],
                'password': found_creds['password'],
                'source': 'xml_elements'
            })
        
        # Look for Windows unattend.xml specific patterns
        if 'unattend' in file_path.lower():
            # Administrator password
            admin_pass = root.findall('.//AdministratorPassword/Value')
            for elem in admin_pass:
                if elem.text:
                    credentials.append({
                        'type': 'credential_pair',
                        'username': 'Administrator',
                        'password': elem.text.strip(),
                        'source': 'unattend_admin'
                    })
            
            # User accounts
            user_accounts = root.findall('.//UserAccounts/AdministratorPassword')
            for elem in user_accounts:
                if elem.text:
                    credentials.append({
                        'type': 'credential_pair',
                        'username': 'Administrator',
                        'password': elem.text.strip(),
                        'source': 'unattend_user_account'
                    })
    
    except ET.ParseError as e:
        # If XML parsing fails, treat as text
        credentials = extract_credentials_from_txt(file_path, file_content)
    
    return credentials

def analyze_file_for_credentials(file_path, share_name, remote_path):
    """Analyze a downloaded file for credentials based on its extension"""
    if not Path(file_path).exists():
        return []
    
    # Check if this is a key file first
    if is_key_file(file_path):
        print(f"  [+] Found key file: {Path(file_path).name}")
        return [{
            'type': 'key_file',
            'filename': Path(file_path).name,
            'file_type': 'cryptographic_key',
            'message': 'Cryptographic key or certificate file found',
            'file_path': file_path,
            'share_name': share_name,
            'remote_path': remote_path
        }]
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"  [-] Error reading {file_path}: {str(e)}")
        return []
    
    if not content.strip():
        return []
    
    # Determine extraction method based on file extension
    file_ext = Path(file_path).suffix.lower()
    
    if file_ext in ['.txt', '.log', '.conf', '.cfg', '.ini']:
        print(f"  [+] Extracting credentials from text file")
        credentials = extract_credentials_from_txt(file_path, content)
    elif file_ext in ['.xml']:
        print(f"  [+] Extracting credentials from XML file")
        credentials = extract_credentials_from_xml(file_path, content)
    else:
        # Default to text extraction
        print(f"  [+] Extracting credentials from file (treating as text)")
        credentials = extract_credentials_from_txt(file_path, content)
    
    # Add file information to each credential
    for cred in credentials:
        cred['file_path'] = file_path
        cred['share_name'] = share_name
        cred['remote_path'] = remote_path
    
    return credentials