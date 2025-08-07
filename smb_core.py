import os
import re
from datetime import datetime

# Administrative/system shares to skip by default
SYSTEM_SHARES = ['C$', 'D$', 'E$', 'F$', 'ADMIN$', 'IPC$', 'print$']

# Interesting file patterns to search for (fixed regex patterns)
INTERESTING_FILES = {
    'credentials': [
        r'.*creds?\.txt$', r'.*credentials?\.txt$', r'.*pass(word)?s?\.txt$',
        r'.*login\.txt$', r'.*auth\.txt$', r'.*secret\.txt$', r'.*accounts?\.txt$',
        # Enhanced credential patterns
        r'.*creds?\..*$',  # Catches creds.txt.txt, creds.bak, etc.
        r'.*credentials?\..*$',  # credentials.backup, etc.
        r'.*pass(word)?s?\..*$',  # passwords.old, password.bak
        r'.*\.creds?$', r'.*\.credentials?$', r'.*\.passwords?$',
        r'.*backup.*pass.*$', r'.*pass.*backup.*$',
        r'.*user.*pass.*$', r'.*admin.*pass.*$',
        r'.*ftp.*creds?.*$', r'.*ssh.*creds?.*$', r'.*db.*creds?.*$',
        r'.*database.*pass.*$', r'.*mysql.*pass.*$', r'.*sql.*creds?.*$',
        r'.*service.*acc.*$', r'.*svc.*acc.*$',  # Service accounts
        r'.*token.*$', r'.*api.*key.*$', r'.*secret.*key.*$',
        r'.*\.htpasswd$', r'.*shadow.*$', r'.*passwd.*$'
    ],
    
    'config': [
        r'.*conf(ig)?\.txt$', r'.*\.conf$', r'.*\.cfg$', r'.*config\.xml$',
        r'.*settings\.txt$', r'.*\.ini$', r'.*web\.config$', r'.*app\.config$',
        # Enhanced config patterns
        r'.*\.properties$', r'.*\.yaml$', r'.*\.yml$', r'.*\.json$',
        r'.*connection.*string.*$', r'.*conn.*str.*$',
        r'.*database\..*$', r'.*db\..*$', r'.*dsn\..*$',
        r'.*\.env$', r'.*environment.*$', r'.*\.local$',
        r'.*appsettings.*$', r'.*settings\..*$',
        r'.*config.*$',           # config123, myconfig, database_config
        r'.*conf.*$',             # conf123, myconf, db_conf
        r'.*setting.*$',
        # Database + config combinations
        r'.*data.*config.*$',     # DATA_CONFIG, database_config
        r'.*db.*config.*$',       # db_config, DB_CONFIG
        r'.*sql.*config.*$',      # sql_config, mysql_config
        r'.*connection.*$',       # connection_string, db_connection
        r'.*conn.*$',            # conn_config, db_conn
        # Common config file patterns without extensions
        r'.*configuration.*$',    # configuration, app_configuration
        r'.*properties.*$',       # app.properties, db_properties
        r'.*environment.*$',      # environment, prod_environment
        r'.*\.env.*$',           # .env, .env.local, .env.backup
        
        # Original enhanced patterns with extensions
        r'.*\.properties$', r'.*\.yaml$', r'.*\.yml$', r'.*\.json$',
        r'.*appsettings.*$', r'.*connection.*string.*$'
    ],
    'unattended': [
        r'.*unattend.*\.xml$', r'.*unattended?\.txt$', r'.*sysprep\.inf$',
        r'.*autounattend\.xml$', r'.*answer.*\.txt$',
    ],
    'keys': [
        r'.*\.key$', r'.*\.pem$', r'.*\.p12$', r'.*\.pfx$', r'.*id_rsa.*$',
        r'.*\.ssh.*$', r'.*private.*key.*$',
        r'.*\.key\..*$', r'.*\.pem\..*$', 
        r'.*cert.*$', r'.*certificate.*$',
        r'.*\.crt$', r'.*\.cer$', r'.*\.der$',
        r'.*keystore.*$', r'.*truststore.*$',
        r'.*\.jks$', r'.*\.p7b$'
    ],
    'sensitive_docs': [
        r'.*password.*\.(txt|doc|docx|pdf)$', r'.*sensitive.*\.(txt|doc|docx|pdf)$',
        r'.*confidential.*\.(txt|doc|docx|pdf)$', r'.*private.*\.(txt|doc|docx|pdf)$',
        # Enhanced document patterns
        r'.*credential.*\.(txt|doc|docx|pdf|xls|xlsx)$',
        r'.*admin.*\.(txt|doc|docx|pdf)$',
        r'.*backup.*\.(txt|doc|docx|pdf)$',
        r'.*install.*\.(txt|doc|docx|pdf)$',  # Installation docs often have default creds
        r'.*setup.*\.(txt|doc|docx|pdf)$',
        r'.*readme.*\.(txt|doc|docx|pdf)$',
        r'.*todo.*\.(txt|doc|docx|pdf)$',
        r'.*notes.*\.(txt|doc|docx|pdf)$'
    ],
    'scripts': [  
        r'.*\.bat$', r'.*\.cmd$', r'.*\.ps1$', r'.*\.vbs$',
        r'.*\.sh$', r'.*\.py$', r'.*\.pl$', r'.*\.sql$',
        r'.*backup.*script.*$', r'.*deploy.*script.*$',
        r'.*install.*script.*$'
    ],
    'database': [ 
    r'.*\.db$', r'.*\.sqlite$', r'.*\.mdb$', r'.*\.accdb$',
    r'.*database.*$', r'.*\.sql$', r'.*dump.*$',
    r'.*backup.*\.sql$',
    r'.*\.xlsx$', r'.*\.xlsm$', r'.*\.xls$'  # Add Excel files
    ], 
    'spreadsheets': [
    r'.*\.xlsx$', r'.*\.xlsm$', r'.*\.xls$', r'.*\.csv$',
    r'.*credential.*\.xlsx$', r'.*password.*\.xlsx$',
    r'.*user.*\.xlsx$', r'.*account.*\.xlsx$',
    r'.*login.*\.xlsx$', r'.*admin.*\.xlsx$'
    ]
}

def is_interesting_file(filename , search_pattern=None):
    """Check if a file matches interesting patterns"""
    filename_lower = filename.lower()
    if search_pattern:
        if search_pattern.lower() in filename_lower:
            return ['search_match']
        else:
            return []
    matches = []
    for category, patterns in INTERESTING_FILES.items():
        for pattern in patterns:
            if re.search(pattern, filename_lower):
                matches.append(category)
                break
    return matches

def should_skip_share(share_name, skip_system=True):
    """Determine if we should skip a share"""
    if not skip_system:
        return False
    return share_name.upper() in [s.upper() for s in SYSTEM_SHARES]

def crawl_share(connection, share_name, path="", level=0, max_level=3, timeout=10, search_filename=None, keyword=None):
    """Recursively crawl a share looking for interesting files"""
    interesting_finds = []
    if level > max_level:
        return interesting_finds
    try:
        indent = "  " * level
        print(f"{indent}[*] Crawling: /{share_name}{path}")
        files = connection.listPath(share_name, path, timeout=timeout)
        for file_info in files:
            if file_info.filename in ['.', '..']:
                continue
            full_path = f"{path}/{file_info.filename}" if path else f"/{file_info.filename}"
            if file_info.isDirectory:
                print(f"{indent}  [DIR]  {file_info.filename}/")
                if level < max_level:
                    sub_finds = crawl_share(
                        connection, share_name, full_path, 
                        level + 1, max_level, timeout, search_filename, keyword
                    )
                    interesting_finds.extend(sub_finds)
            else:
                categories = is_interesting_file(file_info.filename, search_filename)
                
                # If keyword search is enabled
                keyword_matches = []
                should_include = False
                
                if keyword:
                    # Only search in small text files to avoid performance issues
                    if file_info.file_size < 1024 * 1024:  # Less than 1MB
                        # If filename filter is specified, only search in matching files
                        if search_filename:
                            if search_filename.lower() in file_info.filename.lower():
                                keyword_matches = search_file_content(connection, share_name, full_path, keyword, timeout)
                                should_include = len(keyword_matches) > 0
                        else:
                            # Search in all small files
                            keyword_matches = search_file_content(connection, share_name, full_path, keyword, timeout)
                            should_include = len(keyword_matches) > 0
                else:
                    # Original logic when no keyword search - ONLY include files that match interesting patterns
                    should_include = bool(categories)
                
                if should_include:
                    file_size = file_info.file_size
                    size_str = format_file_size(file_size)
                    
                    # Create status string
                    status_parts = []
                    if categories:
                        status_parts.append(f"INTERESTING: {', '.join(categories).upper()}")
                    if keyword_matches:
                        status_parts.append(f"KEYWORD: {len(keyword_matches)} matches")
                    
                    status_str = f" [{'; '.join(status_parts)}]" if status_parts else ""
                    
                    print(f"{indent}  [FILE] {file_info.filename} ({size_str}){status_str}")
                    
                    # Show keyword matches
                    if keyword_matches:
                        for match in keyword_matches[:3]:  # Show first 3 matches
                            print(f"{indent}    Line {match['line_number']}: {match['line_content']}")
                        if len(keyword_matches) > 3:
                            print(f"{indent}    ... and {len(keyword_matches) - 3} more matches")
                    
                    interesting_finds.append({
                        'share': share_name,
                        'path': full_path,
                        'filename': file_info.filename,
                        'size': file_size,
                        'categories': categories,
                        'modified': file_info.last_write_time,
                        'keyword_matches': keyword_matches
                    })
                else:
                    # Only show non-interesting files at shallow levels and when not doing keyword search
                    if level <= 0 and not keyword and not search_filename:  # Only show at root level
                        print(f"{indent}  [FILE] {file_info.filename}")
    except Exception as e:
        print(f"{indent}[-] Error accessing {share_name}{path}: {str(e)}")
    return interesting_finds

def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f}{size_names[i]}"

def test_share_access(connection, share_name, timeout=10):
    """Test if we can access a share"""
    try:
        connection.listPath(share_name, "/", timeout=timeout)
        return True
    except Exception:
        return False

def download_interesting_file(connection, share_name, remote_path, local_path, timeout=10):
    """Download a file from the SMB share"""
    try:
        with open(local_path, 'wb') as file_obj:
            connection.retrieveFile(share_name, remote_path, file_obj, timeout=timeout)
        return True
    except Exception as e:
        print(f"[-] Failed to download {remote_path}: {str(e)}")
        return False 
    
def search_file_content(connection, share_name, file_path, keyword, timeout=10):
    """Search for keyword inside a file's content"""
    try:
        from io import BytesIO
        file_obj = BytesIO()
        connection.retrieveFile(share_name, file_path, file_obj, timeout=timeout)
        
        # Try to decode content as text
        content = file_obj.getvalue()
        try:
            # Try UTF-8 first
            text_content = content.decode('utf-8', errors='ignore')
        except:
            try:
                # Try latin-1 as fallback
                text_content = content.decode('latin-1', errors='ignore')
            except:
                return []
        
        # Search for keyword with wildcard support (case-insensitive)
        matches = []
        lines = text_content.split('\n')

        # Convert keyword to regex pattern if it contains wildcards
        if '*' in keyword or '?' in keyword:
            # Escape special regex characters except * and ?
            escaped_keyword = re.escape(keyword)
            # Replace escaped wildcards with regex equivalents
            pattern = escaped_keyword.replace(r'\*', '.*').replace(r'\?', '.')
            # Compile pattern for case-insensitive matching
            regex_pattern = re.compile(pattern, re.IGNORECASE)
            
            for line_num, line in enumerate(lines, 1):
                if regex_pattern.search(line):
                    matches.append({
                        'line_number': line_num,
                        'line_content': line.strip()[:200]  # Limit line length
                    })
        else:
            # Original simple substring search for non-wildcard keywords
            for line_num, line in enumerate(lines, 1):
                if keyword.lower() in line.lower():
                    matches.append({
                        'line_number': line_num,
                        'line_content': line.strip()[:200]  # Limit line length
                    })
        
        return matches
        
    except Exception as e:
        return []