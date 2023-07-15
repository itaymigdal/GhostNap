

# GhostNap
GhostNap is my implementation of sleep obfuscation in Nim.
It protects the shellcode implant, but also protects the reflective DLL's loaded by the shellcode, as Meterpreter and Cobalt Strike beacons love to do.

The traditional proof:
![](/yay.PNG)

# Why
Most of the sleep obfuscation techniques I encountered, were protecting the image. Regarding protecting shellcodes, [ShellGhost](https://github.com/lem0nSec/ShellGhost) is really awesome, but the only other I know - [ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation), wasn't worked good for me. 
Also, I did not see yet a pure shellcode implants, that do not depend on loading other PE's, so I believe that my solution is kind of filling this gap.
It also coded in Nim - which is the thing :yellow_heart:

## How
1. Installs a hook on `kernel32:Sleep` (so your implant must use it).
2. Allocates executable memory for the shellcode implant. can be improved by allocating non-executable memory and then flip it to executable, but I'm lazy.
3. Installs a hook on `kernel32:VirtualAlloc` (so your implant must not use lower calls like `NtAllocateVirtualMemory`)
4. Copies the shellcode, and executes it via Fiber or by the `CertEnumSystemStore` callback.
5. Any call to `VirtualAlloc` is hooked, and the permission is being compared to `PAGE_READWRITE` | `PAGE_EXECUTE_READ` | `PAGE_EXECUTE_READWRITE` - if yes, we're going to protect this memory page also.
6. Any call to `Sleep` will:
   1. Remove the `X` permission from the shellcode and any other protected page.
   2. Encode the shellcode and any other protected page by single byte xor, or by RC4 using `SystemFunction032`.
   3. Sleep.
   4. Decode each page back.
   5. Add the `X` permission again.


## Installation
Built with Nim 1.6.12.
```
nimble install winim ptr_math nimprotect minhook
```

## Usage
Just edit the config at the source file, it's very commented.

Compile with `-d:release`, unless you want to see verbose prints.

## Credits
- khchen for the great projects [minhook](https://github.com/khchen/minhook) and [winim](https://github.com/khchen/winim)
- s3cur3th1ssh1t for [SystemFunction032 Nim implementation](https://s3cur3th1ssh1t.github.io/SystemFunction032_Shellcode/)
- All the other work done by smarter guys than me on sleep obfuscation


  
