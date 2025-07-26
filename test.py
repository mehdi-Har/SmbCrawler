import argparse
import sys
import os
import re
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
import configparser
from io import StringIO
from smb_core import *
from utils import *
from credential_extractor import *
import socket

try:
    from smb.SMBConnection import SMBConnection
    from smb.base import SharedFile
except ImportError:
    print("Error: pysmb library not installed. Install with: pip install pysmb")
    sys.exit(1)
from adEnum import *

# Add this function to test SMB connectivity before full crawl
def test_smb_connectivity(target, username, password, domain="", port=445, timeout=5):
    """Quick test if SMB is accessible on target"""
    try:
        connection = SMBConnection(
            username, password, "SMBScanner", target,
            domain=domain, use_ntlm_v2=True,
            sign_options=SMBConnection.SIGN_WHEN_SUPPORTED,
            is_direct_tcp=True
        )
        
        connected = connection.connect(target, port, timeout=timeout)
        if connected:
            connection.close()
            return True
        return False
    except Exception:
        return False

def crawl_multiple_targets(targets, username, password, domain="", port=445, timeout=10, 
                          drill_level=0, skip_system=True, download_files=False, extract_creds=False , search_filename=None):
    """Crawl SMB shares on multiple targets"""
    results = []
    successful_targets = []
    
    print(f"[*] Testing SMB connectivity on {len(targets)} targets...")
    
    # First, test connectivity to all targets
    accessible_targets = []
    for target_info in targets:
        target = target_info['target']
        print(f"[*] Testing {target} ({target_info['name']})...")
        
        if test_smb_connectivity(target, username, password, domain, port, timeout=3):
            print(f"[+] {target} - SMB accessible")
            accessible_targets.append(target_info)
        else:
            print(f"[-] {target} - SMB not accessible")
    
    print(f"\n[+] {len(accessible_targets)} of {len(targets)} targets have accessible SMB")
    
    if not accessible_targets:
        print("[-] No accessible SMB targets found")
        return results
    
    # Now crawl accessible targets
    print(f"\n[*] Starting SMB crawling on accessible targets...")
    print("=" * 70)
    
    for i, target_info in enumerate(accessible_targets, 1):
        target = target_info['target']
        computer_name = target_info['name']
        
        print(f"\n[*] [{i}/{len(accessible_targets)}] Crawling {target} ({computer_name})")
        print(f"[*] OS: {target_info.get('os', 'Unknown')}")
        print("-" * 50)
        
        success = list_smb_shares(
            target=target,
            username=username,
            password=password,
            domain=domain,
            port=port,
            timeout=timeout,
            drill_level=drill_level,
            skip_system=skip_system,
            download_files=download_files,
            extract_creds=extract_creds,
            search_filename=search_filename
        )
        
        if success:
            successful_targets.append(target_info)
        
        results.append({
            'target_info': target_info,
            'success': success
        })
    
    print(f"\n{'='*70}")
    print(f"[+] CRAWL SUMMARY:")
    print(f"[+] Total targets scanned: {len(targets)}")
    print(f"[+] SMB accessible: {len(accessible_targets)}")
    print(f"[+] Successfully crawled: {len(successful_targets)}")
    print("=" * 70)
    
    return results
def list_smb_shares(target, username, password, domain="", port=445, timeout=10, drill_level=0, skip_system=True, download_files=False, extract_creds=False , search_filename=None):
    """Connect to SMB server, list shares, and optionally crawl them"""
    try:
        connection = SMBConnection(
            username, 
            password, 
            "SMBCrawler",
            target,
            domain=domain,
            use_ntlm_v2=True,
            sign_options=SMBConnection.SIGN_WHEN_SUPPORTED,
            is_direct_tcp=True
        )
        
        print(f"[*] Connecting to {target}:{port}...")
        
        connected = connection.connect(target, port, timeout=timeout)
        
        if not connected:
            print("[-] Connection failed - authentication or network issue")
            return False
        
        print("[+] Connected successfully!")
        print("[*] Enumerating shares...")
        
        shares = connection.listShares(timeout=timeout)
        
        print(f"\n{'Share Name':<20} {'Type':<10} {'Access':<8} {'Status':<15} {'Comments'}")
        print("-" * 80)
        
        accessible_shares = []
        all_interesting_files = []
        
        for share in shares:
            share_type = {
                0: "Disk",
                1: "Printer", 
                2: "Device",
                3: "IPC"
            }.get(share.type, "Unknown")
            
            comments = share.comments if share.comments else ""
            
            skip_status = ""
            if should_skip_share(share.name, skip_system):
                skip_status = "[SKIPPED]"
                access_status = "SKIPPED"
            elif share.type == 0:
                has_access = test_share_access(connection, share.name, timeout)
                access_status = "READ" if has_access else "DENIED"
                
                if has_access:
                    accessible_shares.append(share.name)
                    skip_status = "[TARGET]"
            else:
                access_status = "N/A"
            
            print(f"{share.name:<20} {share_type:<10} {access_status:<8} {skip_status:<15} {comments}")
        
        print(f"\n[+] Found {len(shares)} shares ({len(accessible_shares)} accessible for crawling)")
        
        if drill_level > 0 and accessible_shares:
            print(f"\n[*] Starting deep crawl (level {drill_level}) on accessible shares...")
            print("=" * 70)
            
            for share_name in accessible_shares:
                print(f"\n[*] Crawling share: {share_name}")
                print("-" * 40)
                
                interesting_files = crawl_share(
                    connection, share_name, "", 0, drill_level, timeout , search_filename
                )
                all_interesting_files.extend(interesting_files)
            
            if all_interesting_files:
                print(f"\n{'='*70}")
                print(f"[+] SUMMARY: Found {len(all_interesting_files)} interesting files:")
                print("=" * 70)
                
                by_category = {}
                for file_info in all_interesting_files:
                    for category in file_info['categories']:
                        if category not in by_category:
                            by_category[category] = []
                        by_category[category].append(file_info)
                
                for category, files in by_category.items():
                    print(f"\n[{category.upper()}] ({len(files)} files):")
                    for file_info in files:
                        size_str = format_file_size(file_info['size'])
                        print(f"  - {file_info['share']}{file_info['path']} ({size_str})")
                
                # Download and analyze files
                all_credentials = []
                if download_files or extract_creds:
                    print(f"\n[*] Downloading and analyzing interesting files...")
                    download_dir = f"smb_loot_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    os.makedirs(download_dir, exist_ok=True)
                    
                    for file_info in all_interesting_files:
                        if file_info['size'] < 10 * 1024 * 1024:  # Only files < 10MB
                            safe_filename = re.sub(r'[<>:"/\\|?*]', '_', file_info['filename'])
                            local_path = os.path.join(download_dir, f"{file_info['share']}_{safe_filename}")
                            
                            print(f"  [*] Downloading {file_info['share']}{file_info['path']} -> {local_path}")
                            if download_interesting_file(connection, file_info['share'], file_info['path'], local_path, timeout):
                                print(f"  [+] Downloaded successfully")
                                
                                # Extract credentials if requested
                                if extract_creds:
                                    print(f"  [*] Analyzing for credentials...")
                                    credentials = analyze_file_for_credentials(
                                        local_path, file_info['share'], file_info['path']
                                    )
                                    if credentials:
                                        print(f"  [+] Found {len(credentials)} item(s)")
                                        all_credentials.extend(credentials)
                                    else:
                                        print(f"  [-] No credentials found")
                            else:
                                print(f"  [-] Download failed")
                        else:
                            print(f"  [-] Skipping {file_info['filename']} (too large: {format_file_size(file_info['size'])})")
                    
                    print(f"\n[+] Downloaded files saved to: {download_dir}")
                    
                    # Print credential summary
                    if all_credentials:
                        print_credentials_summary(all_credentials)
                    elif extract_creds:
                        print(f"\n[*] No credentials extracted from downloaded files")
            else:
                print(f"\n[*] No interesting files found during crawl")
        
        connection.close()
        return True
        
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="SMB Share Crawler with Active Directory enumeration and credential extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target (original functionality)
  python test.py -t 192.168.1.100 -u guest -p ""
  
  # Enumerate AD computers and crawl all accessible SMB shares
  python test.py --ad-enum -dc 192.168.1.10 -u mark -p "P@ssw0rd!" -d test.orange.com -l 2 --extract-creds
  
  # Enumerate AD but only crawl specific targets
  python test.py --ad-enum -dc 192.168.1.10 -u mark -p "P@ssw0rd!" -d test.orange.com --ad-filter "SERVER,WORKSTATION" -l 1

Drill Levels:
  -l 0: List shares only (default)
  -l 1: Crawl root directories of accessible shares
  -l 2: Crawl 2 levels deep
  -l 3: Crawl 3 levels deep (recommended max)
        """
    )
    
    # Target specification (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', 
                             help='Single target IP address or hostname')
    target_group.add_argument('--ad-enum', action='store_true',
                             help='Enumerate targets from Active Directory')
    
    # AD enumeration options
    parser.add_argument('-dc', '--domain-controller', 
                       help='Domain controller IP/hostname (required with --ad-enum)')
    parser.add_argument('--ad-filter', 
                       help='Comma-separated computer names to target (optional)')
    parser.add_argument('--ldap-port', type=int, default=389,
                       help='LDAP port (default: 389)')
    parser.add_argument('--ldap-ssl', action='store_true',
                       help='Use LDAPS (SSL) for AD connection')
    
    # Authentication
    parser.add_argument('-u', '--username', required=True,
                       help='Username for authentication')
    parser.add_argument('-p', '--password', required=True,
                       help='Password for authentication (use "" for blank)')
    parser.add_argument('-d', '--domain', default='',
                       help='Domain name (optional)')
    
    # SMB options
    parser.add_argument('-l', '--level', type=int, default=0,
                       help='Drill level for crawling shares (0=list only, 1-3=crawl depth)')
    parser.add_argument('--port', type=int, default=445,
                       help='SMB port (default: 445)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--include-system', action='store_true',
                       help='Include system shares (C$, ADMIN$, etc.) in crawling')
    parser.add_argument('--download', action='store_true',
                       help='Download interesting files found during crawl')
    parser.add_argument('--extract-creds', action='store_true',
                       help='Extract credentials from downloaded files')
    parser.add_argument('--use-dc-ip', action='store_true',
                   help='Use domain controller IP as base for computer IPs (when DNS fails)')
    # In the argument parser section, add this line:
    parser.add_argument('--filename', 
                   help='Search for files containing this string (case-insensitive)')
    args = parser.parse_args()
    
    # Validation
    if args.level < 0 or args.level > 5:
        print("[-] Error: Drill level must be between 0 and 5")
        sys.exit(1)
    
    if args.ad_enum and not args.domain_controller:
        print("[-] Error: --domain-controller required when using --ad-enum")
        sys.exit(1)
    
    print(f"SMB Share Crawler with AD Enumeration - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Username: {args.username}")
    print(f"Domain: {args.domain if args.domain else '(local)'}")
    print(f"Drill Level: {args.level}")
    print(f"Include System Shares: {args.include_system}")
    print(f"Download Files: {args.download}")
    print(f"Extract Credentials: {args.extract_creds}")
    print("-" * 50)
    
    if args.ad_enum:
        # Active Directory enumeration mode
        print(f"Mode: Active Directory Enumeration")
        print(f"Domain Controller: {args.domain_controller}:{args.ldap_port}")
        print(f"LDAP SSL: {args.ldap_ssl}")
        if args.ad_filter:
            print(f"Target Filter: {args.ad_filter}")
        print("-" * 50)
        
        # Enumerate computers from AD
        computers = enumerate_ad_computers(
            domain_controller=args.domain_controller,
            username=args.username,
            password=args.password,
            domain=args.domain,
            port=args.ldap_port,
            use_ssl=args.ldap_ssl
        )
        
        if not computers:
            print("[-] No computers found in Active Directory")
            sys.exit(1)
        
        # Apply filter if specified
        if args.ad_filter:
            filter_names = [name.strip().upper() for name in args.ad_filter.split(',')]
            computers = [comp for comp in computers if comp['name'].upper() in filter_names]
            print(f"[*] Applied filter, {len(computers)} computers match")
        
        if not computers:
            print("[-] No computers match the specified filter")
            sys.exit(1)
        
        # Display found computers
        print(f"\n[+] Targeting {len(computers)} computer(s):")
        for comp in computers:
            status = "ACTIVE" if comp['active'] else "INACTIVE"
            print(f"  - {comp['name']} ({comp['target']}) [{comp['os']}] [{status}]")
        # Crawl all found computers
        print(f"\n[*] Checking DNS resolution and applying fixes...")
        fixed_computers = []
        
        for comp in computers:
            original_target = comp['target']
            
            # Test if current target is reachable
            try:
                socket.gethostbyname(original_target)
                print(f"[+] {comp['name']}: DNS OK ({original_target})")
                fixed_computers.append(comp)
            except socket.gaierror:
                print(f"[-] {comp['name']}: DNS failed for {original_target}")
                
                # Apply manual fixes for known computers
                fixed_target = None
                
                if 'ORANGEDC' in comp['name'].upper() or 'DC' in comp['name'].upper():
                    # Use the domain controller IP for the DC
                    fixed_target = args.domain_controller
                    print(f"[+] {comp['name']}: Using DC IP -> {fixed_target}")
                
                elif comp['name'].upper() in ['WKS1', 'WKS2']:
                    # For workstations, try NetBIOS name first
                    try:
                        socket.gethostbyname(comp['name'])
                        fixed_target = comp['name']
                        print(f"[+] {comp['name']}: NetBIOS resolved -> {fixed_target}")
                    except socket.gaierror:
                        # If NetBIOS fails, you might need to manually specify IPs
                        # or scan the network. For now, we'll skip these.
                        print(f"[-] {comp['name']}: Could not resolve - will skip")
                        continue
                
                else:
                    # Try NetBIOS name as fallback
                    try:
                        socket.gethostbyname(comp['name'])
                        fixed_target = comp['name']
                        print(f"[+] {comp['name']}: NetBIOS resolved -> {fixed_target}")
                    except socket.gaierror:
                        print(f"[-] {comp['name']}: Could not resolve - will skip")
                        continue
                
                if fixed_target:
                    comp['target'] = fixed_target
                    comp['resolution_method'] = 'manual_override'
                    fixed_computers.append(comp)
        
        # Update computers list with only resolvable targets
        computers = fixed_computers
        
        if not computers:
            print("[-] No computers could be resolved to accessible targets")
            sys.exit(1)
        
        print(f"\n[+] After DNS resolution: {len(computers)} computer(s) accessible:")
        for comp in computers:
            method = comp.get('resolution_method', 'dns')
            print(f"  - {comp['name']} -> {comp['target']} [{method}]")
        results = crawl_multiple_targets(
            targets=computers,
            username=args.username,
            password=args.password,
            domain=args.domain,
            port=args.port,
            timeout=args.timeout,
            drill_level=args.level,
            skip_system=not args.include_system,
            download_files=args.download,
            extract_creds=args.extract_creds,
            search_filename=args.filename
        )
        
        success = any(result['success'] for result in results)
        
    else:
        # Single target mode (original functionality)
        print(f"Mode: Single Target")
        print(f"Target: {args.target}:{args.port}")
        print("-" * 50)
        
        success = list_smb_shares(
            target=args.target,
            username=args.username,
            password=args.password,
            domain=args.domain,
            port=args.port,
            timeout=args.timeout,
            drill_level=args.level,
            skip_system=not args.include_system,
            download_files=args.download,
            extract_creds=args.extract_creds,
            search_filename=args.filename
        )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()