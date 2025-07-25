import os
import re
from datetime import datetime

# Administrative/system shares to skip by default
SYSTEM_SHARES = ['C$', 'D$', 'E$', 'F$', 'ADMIN$', 'IPC$', 'print$']

# Interesting file patterns to search for (fixed regex patterns)
INTERESTING_FILES = {
    'credentials': [
        r'.*creds?\.txt$', r'.*credentials?\.txt$', r'.*pass(word)?s?\.txt$',
        r'.*login\.txt$', r'.*auth\.txt$', r'.*secret\.txt$', r'.*accounts?\.txt$'
    ],
    'config': [
        r'.*conf(ig)?\.txt$', r'.*\.conf$', r'.*\.cfg$', r'.*config\.xml$',
        r'.*settings\.txt$', r'.*\.ini$', r'.*web\.config$', r'.*app\.config$'
    ],
    'unattended': [
        r'.*unattend.*\.xml$', r'.*unattended?\.txt$', r'.*sysprep\.inf$',
        r'.*autounattend\.xml$', r'.*answer.*\.txt$'
    ],
    'keys': [
        r'.*\.key$', r'.*\.pem$', r'.*\.p12$', r'.*\.pfx$', r'.*id_rsa.*$',
        r'.*\.ssh.*$', r'.*private.*key.*$'
    ],
    'sensitive_docs': [
        r'.*password.*\.(txt|doc|docx|pdf)$', r'.*sensitive.*\.(txt|doc|docx|pdf)$',
        r'.*confidential.*\.(txt|doc|docx|pdf)$', r'.*private.*\.(txt|doc|docx|pdf)$'
    ]
}

def is_interesting_file(filename):
    """Check if a file matches interesting patterns"""
    filename_lower = filename.lower()
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

def crawl_share(connection, share_name, path="", level=0, max_level=3, timeout=10):
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
                        level + 1, max_level, timeout
                    )
                    interesting_finds.extend(sub_finds)
            else:
                categories = is_interesting_file(file_info.filename)
                if categories:
                    file_size = file_info.file_size
                    size_str = format_file_size(file_size)
                    print(f"{indent}  [FILE] {file_info.filename} ({size_str}) [INTERESTING: {', '.join(categories).upper()}]")
                    interesting_finds.append({
                        'share': share_name,
                        'path': full_path,
                        'filename': file_info.filename,
                        'size': file_size,
                        'categories': categories,
                        'modified': file_info.last_write_time
                    })
                else:
                    if level <= 1:
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