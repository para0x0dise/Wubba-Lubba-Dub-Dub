#!/usr/bin/env python3
"""
API Hash Lookup Tool
This script computes API hashes using the algorithm found in mw_getAPIbyHash function.

Algorithm:
1. FNV-1a hash of API name
2. Additional bit mixing with multiplier 0x85EBCA6B
3. Add salt 0x114DDB33 to the mixed hash for comparison

The malware compares: mixed_hash == (stored_hash + 0x114DDB33)
Therefore: stored_hash = mixed_hash - 0x114DDB33
"""

import sys
import struct

# Salt value used in the hash comparison (at address 0x10001596)
HASH_SALT = 0x114DDB33


def fnv1a_hash(data):
    """
    Compute FNV-1a hash of the input data.
    
    Args:
        data: bytes or string to hash
    
    Returns:
        32-bit unsigned integer hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # FNV-1a parameters
    FNV_OFFSET_BASIS = 0x811C9DC5
    FNV_PRIME = 0x1000193
    
    hash_value = FNV_OFFSET_BASIS
    
    for byte in data:
        hash_value = ((hash_value ^ byte) * FNV_PRIME) & 0xFFFFFFFF
    
    return hash_value


def apply_mixing(hash_value):
    """
    Apply additional bit mixing to the FNV-1a hash.
    This is the custom transformation found in the malware.
    
    Args:
        hash_value: 32-bit unsigned integer
    
    Returns:
        32-bit unsigned integer mixed hash
    """
    MULTIPLIER = 0x85EBCA6B
    
    # First transformation: hash ^ (hash >> 15)
    temp = (hash_value ^ (hash_value >> 15)) & 0xFFFFFFFF
    
    # Multiply by constant
    temp = (temp * MULTIPLIER) & 0xFFFFFFFF
    
    # Second transformation: temp ^ (temp >> 13)
    result = (temp ^ (temp >> 13)) & 0xFFFFFFFF
    
    return result


def compute_api_hash(api_name, return_mixed=False):
    """
    Compute the full API hash as used in mw_getAPIbyHash.
    
    The malware uses a salted comparison:
      mixed_hash == (stored_hash + SALT)
    Where SALT = 0x114DDB33
    
    Therefore:
      stored_hash = mixed_hash - SALT
    
    Args:
        api_name: API function name (string)
        return_mixed: if True, return the mixed hash (before salt subtraction)
    
    Returns:
        32-bit unsigned integer hash (stored hash by default, mixed if specified)
    """
    # Step 1: FNV-1a hash
    fnv_hash = fnv1a_hash(api_name)
    
    # Step 2: Apply bit mixing (MurmurHash-style avalanche)
    mixed_hash = apply_mixing(fnv_hash)
    
    # Step 3: Calculate stored hash (what appears in the binary)
    # During comparison: mixed_hash == (stored_hash + 0x114DDB33)
    # Therefore: stored_hash = mixed_hash - 0x114DDB33
    if return_mixed:
        return mixed_hash
    else:
        stored_hash = (mixed_hash - HASH_SALT) & 0xFFFFFFFF
        return stored_hash


def load_api_list(filename):
    """
    Load API names from a file (one per line).
    
    Args:
        filename: path to file containing API names
    
    Returns:
        list of API name strings
    """
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []


def create_hash_database(api_names, include_mixed=True):
    """
    Create a hash-to-API name database.
    
    Args:
        api_names: list of API name strings
        include_mixed: if True, also include mixed hashes (before salt subtraction)
    
    Returns:
        dict mapping hash (int) to API name (str)
    """
    db = {}
    for api_name in api_names:
        # Add stored hash (what appears in binary)
        stored_hash = compute_api_hash(api_name)
        db[stored_hash] = api_name
        
        # Also add mixed hash for direct comparison lookups
        if include_mixed:
            mixed_hash = compute_api_hash(api_name, return_mixed=True)
            if mixed_hash not in db:  # Don't overwrite if collision
                db[mixed_hash] = api_name
    return db


def lookup_hash(target_hash, hash_db):
    """
    Look up an API name by its hash.
    
    Args:
        target_hash: hash value to look up (int or hex string)
        hash_db: dict mapping hashes to API names (should include both salted and unsalted)
    
    Returns:
        API name if found, None otherwise
    """
    if isinstance(target_hash, str):
        target_hash = int(target_hash, 16 if target_hash.startswith('0x') else 10)
    
    return hash_db.get(target_hash)


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='API Hash Lookup Tool for mw_getAPIbyHash',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compute hash for a single API name
  python api_hash_lookup.py -c "CreateFileA"
  
  # Build database from API list file
  python api_hash_lookup.py -b api_list.txt
  
  # Lookup a hash value
  python api_hash_lookup.py -l 0x12345678 -f api_list.txt
  
  # Reverse lookup all hashes in a file
  python api_hash_lookup.py -r hashes.txt -f api_list.txt
        """
    )
    
    parser.add_argument('-c', '--compute', metavar='API_NAME',
                       help='Compute hash for a single API name')
    parser.add_argument('-b', '--build', metavar='API_FILE',
                       help='Build hash database from API list file')
    parser.add_argument('-l', '--lookup', metavar='HASH',
                       help='Lookup a single hash value (hex or decimal)')
    parser.add_argument('-f', '--file', metavar='API_FILE',
                       help='API list file for lookup operations')
    parser.add_argument('-r', '--reverse', metavar='HASH_FILE',
                       help='Reverse lookup all hashes in a file')
    parser.add_argument('-o', '--output', metavar='OUTPUT_FILE',
                       help='Output file for database or results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Mode: Compute hash for single API
    if args.compute:
        api_name = args.compute
        hash_value = compute_api_hash(api_name)
        print(f"API Name: {api_name}")
        print(f"Hash:     0x{hash_value:08X} ({hash_value})")
        
        if args.verbose:
            fnv = fnv1a_hash(api_name)
            mixed = apply_mixing(fnv)
            print(f"\nDetailed breakdown:")
            print(f"  FNV-1a:       0x{fnv:08X}")
            print(f"  Mixed:        0x{mixed:08X}")
            print(f"  Stored:       0x{hash_value:08X}")
            print(f"  Salt:         0x{HASH_SALT:08X}")
            print(f"  Mixed (calc): 0x{(hash_value + HASH_SALT) & 0xFFFFFFFF:08X} (should match Mixed above)")
        return
    
    # Mode: Build database
    if args.build:
        api_names = load_api_list(args.build)
        if not api_names:
            sys.exit(1)
        
        print(f"Loading {len(api_names)} API names from {args.build}...")
        hash_db = create_hash_database(api_names)
        print(f"Built database with {len(hash_db)} entries.")
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                # Convert int keys to hex strings for JSON
                json_db = {f"0x{k:08X}": v for k, v in hash_db.items()}
                json.dump(json_db, f, indent=2)
            print(f"Database saved to {args.output}")
        else:
            # Print some examples
            print("\nSample entries:")
            for i, (hash_val, api_name) in enumerate(list(hash_db.items())[:10]):
                print(f"  0x{hash_val:08X} -> {api_name}")
            if len(hash_db) > 10:
                print(f"  ... and {len(hash_db) - 10} more")
        return
    
    # Mode: Lookup single hash
    if args.lookup:
        if not args.file:
            print("Error: --file required for lookup operations")
            sys.exit(1)
        
        api_names = load_api_list(args.file)
        if not api_names:
            sys.exit(1)
        
        hash_db = create_hash_database(api_names)
        result = lookup_hash(args.lookup, hash_db)
        
        if result:
            print(f"Hash {args.lookup} -> {result}")
            
            # Show detailed info in verbose mode
            if args.verbose:
                hash_val = int(args.lookup, 16 if args.lookup.startswith('0x') else 10)
                computed_stored = compute_api_hash(result)
                computed_mixed = compute_api_hash(result, return_mixed=True)
                print(f"\nVerification:")
                print(f"  Computed stored: 0x{computed_stored:08X}")
                print(f"  Computed mixed:  0x{computed_mixed:08X}")
                if hash_val == computed_stored:
                    print(f"  Match type: Stored hash")
                elif hash_val == computed_mixed:
                    print(f"  Match type: Mixed hash")
        else:
            hash_val = int(args.lookup, 16 if args.lookup.startswith('0x') else 10)
            mixed_val = (hash_val + HASH_SALT) & 0xFFFFFFFF
            stored_val = (hash_val - HASH_SALT) & 0xFFFFFFFF
            
            print(f"Hash {args.lookup} not found in database")
            print(f"\nNote: Database includes both stored and mixed hashes.")
            print(f"If this is a stored hash, the mixed hash would be: 0x{mixed_val:08X}")
            print(f"If this is a mixed hash, the stored hash would be:  0x{stored_val:08X}")
            print(f"The API name may not be in the provided list.")
        return
    
    # Mode: Reverse lookup from file
    if args.reverse:
        if not args.file:
            print("Error: --file required for lookup operations")
            sys.exit(1)
        
        # Load API database
        api_names = load_api_list(args.file)
        if not api_names:
            sys.exit(1)
        
        print(f"Building hash database from {len(api_names)} API names...")
        hash_db = create_hash_database(api_names)
        
        # Load hashes to lookup
        try:
            with open(args.reverse, 'r') as f:
                hash_lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Error: File '{args.reverse}' not found.")
            sys.exit(1)
        
        results = []
        found_count = 0
        
        print(f"\nLooking up {len(hash_lines)} hashes...\n")
        
        for hash_str in hash_lines:
            result = lookup_hash(hash_str, hash_db)
            if result:
                output = f"{hash_str} -> {result}"
                results.append(output)
                print(f"[+] {output}")
                found_count += 1
            else:
                output = f"{hash_str} -> NOT FOUND"
                results.append(output)
                print(f"[-] {output}")
        
        print(f"\nResults: {found_count}/{len(hash_lines)} found")
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write('\n'.join(results) + '\n')
            print(f"Results saved to {args.output}")
        return
    
    # No valid mode selected
    parser.print_help()


if __name__ == '__main__':
    main()
