#!/usr/bin/env python3
"""
AutoIt Malware Deobfuscator for R.au3
Decodes VOCATIONALFDA encoded strings and extracts payloads
"""

import re
import sys
from pathlib import Path

def decode_vocationalfda(encoded_str, key):
    """
    Decode VOCATIONALFDA encoded strings
    Format: "112N106N119..." with a numeric key
    Algorithm: Split by 'N', subtract key from each number, convert to chr
    """
    try:
        # Split by 'N' and convert to integers
        numbers = [int(x) for x in encoded_str.split('N') if x.strip()]
        # Subtract key and convert to characters
        decoded = ''.join(chr(num - key) for num in numbers)
        return decoded
    except Exception as e:
        return f"[DECODE_ERROR: {e}]"

def extract_vocationalfda_calls(content):
    """
    Extract all VOCATIONALFDA function calls from the script
    Returns list of (original_call, encoded_string, key, decoded_string)
    """
    # Pattern to match VOCATIONALFDA("...", numeric_expression)
    pattern = r'VOCATIONALFDA\("([^"]+)",\s*([^\)]+)\)'
    
    matches = []
    for match in re.finditer(pattern, content):
        encoded_str = match.group(1)
        key_expr = match.group(2).strip()
        
        # Evaluate simple mathematical expressions for the key
        try:
            # Handle simple expressions like "8 - 3", "1 + 0", etc.
            key = eval(key_expr)
            decoded = decode_vocationalfda(encoded_str, key)
            matches.append({
                'original': match.group(0),
                'encoded': encoded_str,
                'key_expr': key_expr,
                'key': key,
                'decoded': decoded,
                'position': match.start()
            })
        except Exception as e:
            matches.append({
                'original': match.group(0),
                'encoded': encoded_str,
                'key_expr': key_expr,
                'key': None,
                'decoded': f"[KEY_EVAL_ERROR: {e}]",
                'position': match.start()
            })
    
    return matches

def deobfuscate_script(input_file, output_file):
    """
    Read the obfuscated script and create a deobfuscated version
    """
    print(f"[*] Reading obfuscated script: {input_file}")
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    print(f"[*] Extracting and decoding VOCATIONALFDA calls...")
    matches = extract_vocationalfda_calls(content)
    
    print(f"[+] Found {len(matches)} encoded strings")
    
    # Replace encoded strings with decoded ones (in reverse order to maintain positions)
    deobfuscated = content
    for match in reversed(matches):
        decoded = match['decoded']
        # Create a comment showing the decoded string
        #replacement = f'"{decoded}" /* was: VOCATIONALFDA(..., {match["key_expr"]}) */'
        deobfuscated = (
            deobfuscated[:match['position']] + 
            #replacement + 
            f'"{decoded}"' + 
            deobfuscated[match['position'] + len(match['original']):]
        )
    
    print(f"[*] Writing deobfuscated script: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(deobfuscated)
    
    print(f"[+] Deobfuscation complete!")
    return matches


def export_decoded_strings(matches, output_file):
    """
    Export all decoded strings to a text file for analysis
    """
    print(f"\n[*] Exporting decoded strings to: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("ALL DECODED STRINGS FROM R.au3\n")
        f.write("="*80 + "\n\n")
        
        for i, match in enumerate(matches, 1):
            f.write(f"[{i}] Key: {match['key']} ({match['key_expr']})\n")
            f.write(f"Encoded: {match['encoded'][:60]}{'...' if len(match['encoded']) > 60 else ''}\n")
            f.write(f"Decoded: {match['decoded']}\n")
            f.write("-"*80 + "\n")
    
    print(f"[+] Exported {len(matches)} decoded strings")

def main():
    print("="*80)
    print("AutoIt Malware Deobfuscator for R.au3")
    print("="*80)
    
    input_file = str(input("Enter the input file path: "))
    output_deobfuscated = str(input("Enter the output deobfuscated file path: "))
    output_strings = str(input("Enter the output decoded strings file path: "))
    
    if not Path(input_file).exists():
        print(f"[!] Error: {input_file} not found!")
        sys.exit(1)
    
    # Deobfuscate the script
    deobfuscate_script(input_file, output_deobfuscated)

    print("\n" + "="*80)
    print("[+] Analysis complete!")
    print(f"[+] Deobfuscated script: {output_deobfuscated}")
    print(f"[+] Decoded strings list: {output_strings}")
    print("="*80)

if __name__ == "__main__":
    main()
