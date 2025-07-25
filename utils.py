def print_credentials_summary(all_credentials):
    """Print a summary of all found credentials"""
    if not all_credentials:
        return
    
    # Separate credential pairs from individual fields
    credential_pairs = [cred for cred in all_credentials if cred['type'] == 'credential_pair']
    individual_fields = [cred for cred in all_credentials if cred['type'] == 'single_field']
    key_files = [cred for cred in all_credentials if cred['type'] == 'key_file']
    
    if credential_pairs:
        print(f"\n{'='*70}")
        print(f"[+] CREDENTIAL EXTRACTION RESULTS:")
        print("=" * 70)
        
        for cred in credential_pairs:
            share_name = cred.get('share_name', 'unknown')
            remote_path = cred.get('remote_path', 'unknown')
            
            print(f"\n[PWNED] {share_name}{remote_path}")
            print(f"  Username: {cred['username']}")
            print(f"  Password: {cred['password']}")
            
            # Additional context
            if 'line' in cred:
                print(f"  Line: {cred['line']}")
            if 'context' in cred:
                print(f"  Context: {cred['context'][:100]}...")
            if 'source' in cred:
                print(f"  Source: {cred['source']}")
            if 'section' in cred:
                print(f"  Section: {cred['section']}")
    
    # Only show individual fields if no pairs were found
    if individual_fields and not credential_pairs:
        print(f"\n{'='*70}")
        print(f"[+] INDIVIDUAL CREDENTIAL FIELDS FOUND:")
        print("=" * 70)
        
        for cred in individual_fields:
            share_name = cred.get('share_name', 'unknown')
            remote_path = cred.get('remote_path', 'unknown')
            
            print(f"\n[INFO] {share_name}{remote_path}")
            print(f"  {cred['field'].title()}: {cred['value']}")
            
            if 'line' in cred:
                print(f"  Line: {cred['line']}")
            if 'context' in cred:
                print(f"  Context: {cred['context'][:100]}...")
    if key_files:
        print(f"\n{'='*70}")
        print(f"[+] KEY FILES FOUND:")
        print("=" * 70)
        for key_file in key_files:
            print(f"  - {key_file['filename']} (from {key_file['share_name']}{key_file['remote_path']})")
            print(f"    Type: {key_file['file_type']}")
            print(f"    Note: {key_file['message']}")
        print()
    # Summary
    if credential_pairs:
        print(f"\n[+] Total credential pairs found: {len(credential_pairs)}")
    elif individual_fields:
        print(f"\n[+] Total individual fields found: {len(individual_fields)} (no complete pairs)")
    
    return len(credential_pairs)