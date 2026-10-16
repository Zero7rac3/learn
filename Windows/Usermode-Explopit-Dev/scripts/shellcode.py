import ctypes
from keystone import *


CODE = (
    # ==========================================================================
    # 1. INITIALIZATION & STACK PREPARATION
    # ==========================================================================
    "start:                                 "
    "   mov   ebp, esp                     ;"   # Save base pointer
    "   add   esp, 0xfffff9f0              ;"   # Clear stack space (~1500 bytes, null-byte free)

    # ==========================================================================
    # 2. DYNAMICALLY FIND KERNEL32.DLL IN MEMORY (PEB Walk)
    # ==========================================================================
    "find_kernel32:                       "
    "   xor   ecx, ecx                     ;"   # ECX = 0
    "   mov   esi, fs:[ecx+0x30]           ;"   # FS:[0x30] = PEB
    "   mov   esi, [esi+0x0C]              ;"   # PEB->Ldr
    "   mov   esi, [esi+0x1C]              ;"   # InInitializationOrderModuleList

    "next_module:                         "
    "   mov   ebx, [esi+0x08]              ;"   # EBX = DLL Base Address
    "   mov   edi, [esi+0x20]              ;"   # EDI = DLL Name Pointer
    "   mov   esi, [esi]                   ;"   # ESI = Next module
    "   cmp   word ptr [edi+12*2], cx      ;"   # Check for end of name (kernel32.dll = 12 WChars)
    "   jne   next_module                  ;"

    # ==========================================================================
    # 3. GET-PC TRICK (Save EAT Parser Address)
    # ==========================================================================
    "find_function_shorten:               "
    "   jmp find_function_shorten_bnc      ;"

    "find_function_ret:                   "
    "   pop esi                            ;"   # Retrieve EIP from stack
    "   mov [ebp+0x04], esi                ;"   # Save pointer to 'find_function'
    "   jmp resolve_symbols_kernel32       ;"

    "find_function_shorten_bnc:           "
    "   call find_function_ret             ;"

    # ==========================================================================
    # 4. THE FUNCTION FINDER (EAT Parser)
    # ==========================================================================
    "find_function:                       "
    "   pushad                             ;"
    "   mov   eax, [ebx+0x3c]              ;"   # PE Header
    "   mov   edi, [ebx+eax+0x78]          ;"   # Export Directory
    "   add   edi, ebx                     ;"
    "   mov   ecx, [edi+0x18]              ;"   # Number of Functions
    "   mov   eax, [edi+0x20]              ;"   # Address Table of Names RVA
    "   add   eax, ebx                     ;"
    "   mov   [ebp-4], eax                 ;"

    "find_function_loop:                  "
    "   jecxz find_function_finished       ;"
    "   dec   ecx                          ;"
    "   mov   eax, [ebp-4]                 ;"
    "   mov   esi, [eax+ecx*4]             ;"
    "   add   esi, ebx                     ;"

    "compute_hash:                        "
    "   xor   eax, eax                     ;"
    "   cdq                                ;"
    "   cld                                ;"

    "compute_hash_again:                  "
    "   lodsb                              ;"
    "   test  al, al                       ;"
    "   jz    find_function_compare        ;"
    "   ror   edx, 0x0d                    ;"   # ROR 13 Hash
    "   add   edx, eax                     ;"
    "   jmp   compute_hash_again           ;"

    "find_function_compare:               "
    "   cmp   edx, [esp+0x24]              ;"   # Compare hash
    "   jnz   find_function_loop           ;"

    "   mov   edx, [edi+0x24]              ;"   # Ordinal Table RVA
    "   add   edx, ebx                     ;"
    "   mov   cx,  [edx+2*ecx]             ;"
    "   mov   edx, [edi+0x1c]              ;"   # Address Table RVA
    "   add   edx, ebx                     ;"
    "   mov   eax, [edx+4*ecx]             ;"
    "   add   eax, ebx                     ;"   # EAX = Function address
    "   mov   [esp+0x1c], eax              ;"   # Preserve EAX after popad

    "find_function_finished:              "
    "   popad                              ;"
    "   ret                                ;"

    # ==========================================================================
    # 5. RESOLVE SYMBOLS (ExitProcess & CopyFileA)
    # ==========================================================================
    "resolve_symbols_kernel32:            "
    "   push  0x73e2d87e                   ;"   # Hash for "ExitProcess"
    "   call  dword ptr [ebp+0x04]         ;"
    "   mov   [ebp+0x10], eax              ;"   # Store address at EBP+0x10

    "   push  0x4c0a0c64                   ;"   # Hash for "CopyFileA" (0x4c0a0c64)
    "   call  dword ptr [ebp+0x04]         ;"
    "   mov   [ebp+0x14], eax              ;"   # Store address at EBP+0x14

    # ==========================================================================
    # 6. PUSH STRINGS ONTO THE STACK
    # ==========================================================================
    # --- String 1: "C:\test.txt" (lpExistingFileName) ---
    "   mov eax, 0xFF8B878C              ;"   # Negative value for "txt\0"
    "   neg eax                            ;"   # 0x00747874
    "   push eax                           ;"
    "   push 0x2E747365                    ;"   # "est."
    "   push 0x745C3A43                    ;"   # "C:\t"
    "   mov esi, esp                       ;"   # ESI = Pointer to lpExistingFileName

    # --- String 2: "C:\test2.txt" (lpNewFileName) ---
    "   mov eax, 0xFF8B87CE              ;"   # Negative value for "2.txt\0"
    "   neg eax                            ;"   # 0x00747832
    "   push eax                           ;"
    "   push 0x74736574                    ;"   # "test"
    "   push 0x745C3A43                    ;"   # "C:\"
    "   mov edi, esp                       ;"   # EDI = Pointer to lpNewFileName

    # ==========================================================================
    # 7. PUSH PARAMETERS & CALL COPYFILEA (stdcall: 3 parameters)
    # ==========================================================================
    "   xor ecx, ecx                       ;"   # ECX = 0 (FALSE = Allow overwrite)

    # Parameter 3: bFailIfExists (0 / FALSE)
    "   push ecx                           ;"  

    # Parameter 2: lpNewFileName ("C:\test2.txt")
    "   push edi                           ;"  

    # Parameter 1: lpExistingFileName ("C:\test.txt")
    "   push esi                           ;"  

    # Call CopyFileA
    "   call dword ptr [ebp+0x14]          ;"  

    # ==========================================================================
    # 8. CLEANLY TERMINATE THE PROCESS
    # ==========================================================================
    "   push 0                             ;"   # Exit code 0
    "   call dword ptr [ebp+0x10]          ;"   # Call ExitProcess(0)

)

# Assembly
try:
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    shellcode = bytes(encoding)
    print(f"[+] Successfully assembled! Length: {len(shellcode)} bytes")
    print(f"[+] Hex Format: \\x" + "\\x".join(f"{b:02x}" for b in shellcode))
except KsError as e:
    print(f"[-] Keystone Error: {e}")