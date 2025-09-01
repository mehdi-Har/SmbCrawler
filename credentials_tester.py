
import socket
import paramiko
import ftplib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def test_ssh_login(host, username, password, port=22, timeout=10):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            username=username,
            password=password,
            port=port,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout
        )
        client.close()
        return {'success': True, 'protocol': 'SSH', 'error': None}
    except paramiko.AuthenticationException:
        return {'success': False, 'protocol': 'SSH', 'error': 'Authentication failed'}
    except paramiko.SSHException as e:
        return {'success': False, 'service': 'SSH', 'error': f'SSH error: {str(e)}'}
    except socket.timeout:
        return {'success': False, 'service': 'SSH', 'error': 'Connection timeout'}
    except Exception as e:
        return {'success': False, 'service': 'SSH', 'error': f'Connection error: {str(e)}'}
def test_ftp_login(host, username, password, port=21, timeout=10):
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(host=host, port=port , timeout=timeout)
        ftp.login(user=username,passwd=password)
        ftp.quit()
        return {'success': True, 'protocol': 'FTP', 'error': None}
    except  ftplib.error_perm as e:
        error_msg  = str(e).lower()
        if '530' in error_msg or 'login' in error_msg or 'authentication' in error_msg:
            return {'success': False, 'protocol': 'FTP', 'error': 'Authentication failed'}
        else:
            return {'success': False, 'protocol': 'FTP', 'error': f'FTP error: {str(e)}'}
    except socket.timeout:
        return {'success': False, 'service': 'FTP', 'error': 'Connection timeout'}
    except Exception as e:
        return {'success': False, 'service': 'FTP', 'error': f'Connection error: {str(e)}'}
def determine_credential_services(credential):
    services_to_test = []
    context = credential.get('context', '').lower()
    source = credential.get('source', '').lower()
    target = credential.get('target', '').lower()
    protocol = credential.get('protocol', '').lower()
    description = credential.get('description', '').lower()
    all_text = f"{context} {source} {target} {protocol} {description}".lower()
    
    # Check for specific service indicators
    ssh_keywords = ['ssh', 'sftp', 'scp', 'openssh', 'putty', 'terminal', 'shell', 'linux', 'unix']
    if any(keyword in all_text for keyword in ssh_keywords):
        services_to_test.append('ssh')
    
    ftp_keywords = ['ftp', 'ftps', 'file transfer', 'filezilla']
    if any(keyword in all_text for keyword in ftp_keywords):
        services_to_test.append('ftp')
    
 
    
    return services_to_test
def test_credential_on_services(credential, target_host, services_to_test=None, timeout=10):
    if services_to_test is None:
        services_to_test = determine_credential_services(credential)
    results = []
    username = credential.get('username', '')
    password = credential.get('password', '')
    if not username or not password:
        return results
    
    print(f"    [*] Testing {username}:**** against {', '.join(services_to_test).upper()}")
    
    if services_to_test:
        for service in services_to_test:
            if service.lower() == 'ssh':
                result = test_ssh_login(target_host, username, password, timeout=timeout)
                results.append(result)
                
            elif service.lower() == 'ftp':
                result = test_ftp_login(target_host, username, password, timeout=timeout)
                results.append(result)
    
    return results
def test_credentials_batch(credentials, target_host, max_workers=5, timeout=10):
    """Test multiple credentials concurrently with rate limiting"""
    all_results = []
    
    def test_single_credential(cred):
        services = determine_credential_services(cred)
        if not services:
            return None
            
        results = test_credential_on_services(cred, target_host, services, timeout)
        return {
            'credential': cred,
            'test_results': results
        }
    
    # Use ThreadPoolExecutor for concurrent testing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all credential tests
        future_to_cred = {
            executor.submit(test_single_credential, cred): cred 
            for cred in credentials
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_cred):
            result = future.result()
            if result:
                all_results.append(result)
            
            # Small delay to avoid overwhelming the target
            time.sleep(0.5)
    
    return all_results
def print_credentials_with_tests(credentials, target_host=None):
    """Enhanced credential summary with service testing using extracted targets"""
    if not credentials:
        return
    
    print(f"\n{'='*80}")
    print(f"[+] CREDENTIAL EXTRACTION RESULTS:")
    print(f"{'='*80}")
    
    cred_pairs = [cred for cred in credentials if cred.get('type') == 'credential_pair']
    key_files = [cred for cred in credentials if cred.get('type') == 'key_file']
    
    if cred_pairs:
        print(f"\n[+] Found {len(cred_pairs)} credential pairs:")
        print("-" * 80)
        
        for i, cred in enumerate(cred_pairs, 1):
            username = cred.get('username', 'N/A')
            password = cred.get('password', 'N/A')
            source_file = cred.get('file_path', 'Unknown')
            context = cred.get('context', 'No context')
            
            print(f"\n[{i}] {username} : {password}")
            print(f"    Source: {source_file}")
            print(f"    Context: {context}")
            
            # Show additional details
            if cred.get('target'):
                print(f"    Target: {cred['target']}")
            if cred.get('protocol'):
                print(f"    Protocol: {cred['protocol'].upper()}")
            
            # Determine targets to test against
            targets_to_test = []
            
            # Priority 1: Explicit target host from credential
            if cred.get('target_host'):
                targets_to_test = [cred['target_host']]
                print(f"    Target Host: {cred['target_host']}")
            
            # Priority 2: Potential targets found in file
            elif cred.get('potential_targets'):
                targets_to_test = cred['potential_targets'][:3]  # Limit to first 3
                print(f"    Potential Targets: {', '.join(targets_to_test)}")
            
            # Test credentials if we have targets
            if targets_to_test:
                services = determine_credential_services(cred)
                if services:
                    print(f"    Testing against {len(targets_to_test)} target(s)...")
                    
                    for target in targets_to_test:
                        print(f"    → Testing {target}:")
                        test_results = test_credential_on_services(
                            cred, target, services, timeout=5
                        )
                        
                        for test_result in test_results:
                            service = test_result['service']
                            if test_result['success']:
                                print(f"      ✓ {service}: LOGIN SUCCESSFUL")
                            else:
                                print(f"      ✗ {service}: {test_result['error']}")
                else:
                    print(f"    [*] No testable services detected")
            else:
                print(f"    [*] No target hosts found - no testing performed")
    
    if key_files:
        print(f"\n[+] Found {len(key_files)} key/certificate files:")
        print("-" * 80)
        for i, key_file in enumerate(key_files, 1):
            print(f"[{i}] {key_file.get('filename', 'Unknown')}")
            print(f"    Type: {key_file.get('file_type', 'Unknown')}")
            print(f"    Path: {key_file.get('file_path', 'Unknown')}")
    
    print(f"\n{'='*80}")