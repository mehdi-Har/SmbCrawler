import socket
try:
    from ldap3 import Server, Connection, ALL, SUBTREE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

def resolve_computer_targets(computers, domain_controller_ip):
    """Resolve computer targets to IP addresses when DNS names fail"""
    resolved_computers = []
    
    for comp in computers:
        original_target = comp['target']
        resolved_target = None
        
        # Try original target first (DNS name)
        print(f"[*] Resolving {comp['name']} ({original_target})...")
        
        try:
            # Test if we can resolve the DNS name
            socket.gethostbyname(original_target)
            resolved_target = original_target
            print(f"[+] DNS resolved: {original_target}")
        except socket.gaierror:
            print(f"[-] DNS resolution failed for {original_target}")
            
            # Try to guess IP based on domain controller subnet
            # This assumes computers are in the same subnet as DC
            if domain_controller_ip:
                try:
                    # Extract subnet from DC IP (assumes /24)
                    dc_parts = domain_controller_ip.split('.')
                    if len(dc_parts) == 4:
                        subnet_base = '.'.join(dc_parts[:3])
                        
                        # Try common IP ranges (you might need to adjust this)
                        for i in range(1, 255):
                            test_ip = f"{subnet_base}.{i}"
                            
                            # Quick connectivity test
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(1)
                                result = sock.connect_ex((test_ip, 445))  # Test SMB port
                                sock.close()
                                
                                if result == 0:  # Connection successful
                                    # Try to get hostname to verify it's our target
                                    try:
                                        hostname = socket.gethostbyaddr(test_ip)[0]
                                        if comp['name'].lower() in hostname.lower():
                                            resolved_target = test_ip
                                            print(f"[+] Found via IP scan: {comp['name']} -> {test_ip}")
                                            break
                                    except:
                                        # If reverse DNS fails, we can still try the IP
                                        # but we'll be less certain it's the right machine
                                        pass
                            except:
                                continue
                                
                except Exception as e:
                    print(f"[-] IP scanning failed: {e}")
            
            # Fallback: try just the computer name (NetBIOS)
            if not resolved_target:
                try:
                    netbios_name = comp['name']
                    socket.gethostbyname(netbios_name)
                    resolved_target = netbios_name
                    print(f"[+] NetBIOS resolved: {netbios_name}")
                except socket.gaierror:
                    print(f"[-] NetBIOS resolution also failed for {netbios_name}")
        
        if resolved_target:
            comp['target'] = resolved_target
            comp['resolution_method'] = 'dns' if resolved_target == original_target else 'alternative'
            resolved_computers.append(comp)
        else:
            print(f"[-] Could not resolve {comp['name']} - skipping")
    
    return resolved_computers
def enumerate_ad_computers(domain_controller, username, password, domain="", port=389, use_ssl=False):
    """Enumerate Windows computers from Active Directory"""
    if not LDAP_AVAILABLE:
        print("[-] Error: ldap3 library not installed. Install with: pip install ldap3")
        return []
    
    computers = []
    try:
        # Construct server URL
        protocol = "ldaps" if use_ssl else "ldap"
        server_url = f"{protocol}://{domain_controller}:{port}"
        server = Server(server_url, get_info=ALL)
        
        # Format username for LDAP bind
        if domain and '@' not in username:
            bind_user = f"{username}@{domain}"
        elif domain and '\\' not in username:
            bind_user = f"{domain}\\{username}"
        else:
            bind_user = username
        
        print(f"[*] Connecting to AD server: {server_url}")
        print(f"[*] Binding as: {bind_user}")
        
        conn = Connection(server, user=bind_user, password=password, auto_bind=True)
        
        # Search for computer objects
        domain_dn = ','.join([f"DC={part}" for part in domain.split('.')] if domain else ["DC=local"])
        search_filter = "(&(objectClass=computer)(operatingSystem=Windows*))"
        
        print(f"[*] Searching for Windows computers in: {domain_dn}")
        conn.search(
            search_base=domain_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['name', 'dNSHostName', 'operatingSystem', 'lastLogonTimestamp', 'pwdLastSet']
        )
        
        print(f"[+] Found {len(conn.entries)} Windows computer(s)")
        
        for entry in conn.entries:
            computer_name = str(entry.name) if entry.name else "Unknown"
            dns_name = str(entry.dNSHostName) if entry.dNSHostName else None
            os_info = str(entry.operatingSystem) if entry.operatingSystem else "Windows"
            
            # Use DNS name if available, otherwise computer name
            target_host = dns_name if dns_name else computer_name
            
            computers.append({
                'name': computer_name,
                'dns_name': dns_name,
                'target': target_host,
                'os': os_info,
                'active': bool(entry.lastLogonTimestamp)
            })
        
        conn.unbind()
        
        # Resolve targets to working IPs/names
        if computers:
            print(f"\n[*] Resolving computer targets...")
            computers = resolve_computer_targets(computers, domain_controller)
        
        return computers
        
    except Exception as e:
        print(f"[-] Error enumerating AD computers: {str(e)}")
        return []