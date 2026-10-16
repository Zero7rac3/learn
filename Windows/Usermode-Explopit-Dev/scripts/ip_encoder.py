import struct

def find_xor_ip(ip_str):
    """
    Calculates an XOR value for an IP address that is free of bad bytes (\x00).
    """
    # 1. Convert IP into a 4-byte hex format (e.g., "192.168.100.1" -> b'\xc0\xa8\xd0\x01')
    try:
        ip_bytes = socket_inet_aton(ip_str)
    except:
        # Fallback if socket is not directly imported
        parts = list(map(int, ip_str.split('.')))
        ip_bytes = struct.pack('4B', *parts)
    
    target_int = struct.unpack("<I", ip_bytes)[0]
    print(f"[*] Target IP: {ip_str} (Hex: {hex(target_int)})")
    print(f"[*] Searching for a clean XOR key (without \\x00)...")

    # We search for a 4-byte XOR key that does not produce null bytes during the XOR operation
    # and where the modified value also contains no null bytes.
    for key in range(0x01000000, 0xFFFFFFFF, 0x01010101): # Simplified search for clean XORs
        modified = target_int ^ key
        
        # Check if neither the modified value nor the key contains null bytes
        if not has_bad_bytes(modified) and not has_bad_bytes(key):
            print(f"\n[+] Match found!")
            print(f"    Base value (mov eax, 0x{modified:08x}): {has_bad_bytes(modified)}")
            print(f"    XOR key    (xor eax, 0x{key:08x}): {has_bad_bytes(key)}")
            
            print("\n--- Copy this assembly block into your shellcode ---")
            print(f'    "    mov    eax, 0x{modified:08x}    ;"')
            print(f'    "    xor    eax, 0x{key:08x}    ;"')
            print(f'    "    push    eax                ;"')
            return

    print("[-] No perfect key found. Try a different approach.")

def socket_inet_aton(ip):
    parts = list(map(int, ip.split('.')))
    return struct.pack('4B', parts[0], parts[1], parts[2], parts[3])

def has_bad_bytes(val):
    """Checks if an integer contains a null byte."""
    packed = struct.pack("<I", val)
    return b'\x00' in packed

if __name__ == "__main__":
    print("=" * 60)
    print(" IP-XOR-Generator (Null-Byte Free)")
    print("=" * 60)
    user_ip = input("Enter your target IP (e.g., 192.168.1.50): ").strip()
    find_xor_ip(user_ip)