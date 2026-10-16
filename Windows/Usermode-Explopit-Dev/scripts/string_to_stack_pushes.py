def string_to_pushes(s):
    data = s.encode("ascii") + b"\x00"

    while len(data) % 4 != 0:
        data += b"\x00"

    print(f"String: {s}\n")

    for i in range(len(data) - 4, -1, -4):
        chunk = data[i:i+4]

        # Little Endian DWORD
        value = int.from_bytes(chunk, byteorder="little")

        print(f"push 0x{value:08x}    ; {chunk!r}")


# Beispiel
string_to_pushes(r"test.exe")