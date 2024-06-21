# NewStartCTF2023-Week2-Reverse


# PZthon

首先放到Die里面查壳：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010102606145.png)

壳没查到，但是发现使用PyInstaller打包的，于是这题就是Python逆向的思路。由于网上所提供的大部分工具都对python3.9无效，我这里提供一个通杀的办法。

## 0x01 exe解包

这里使用的工具是pyinstxtractor，下载方法是：

```bash
git clone https://github.com/extremecoders-re/pyinstxtractor.git
```

将待解包的exe放入同一个文件夹，然后运行：

```
python pyinstxtractor.py test.exe
```

完成后，文件夹下面会有一个test.exe_extracted的文件夹（名字可能不同）

我们需要的文件是：（文件名）.pyc和struct.pyc

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010103428003.png)

注意，这里可能没有pyc的后缀名，那么很可能是你使用的pyinstxtractor的版本过低，如果确认版本的话，请自行添加.pyc后缀。

## 0x02 补充magic number

magic number是在pyc文件开头的一段表示python版本的数，解包出来的pyc文件很可能会magic number缺失，需要手动补全。有很多方法可以查到magic number，但是最简单的还是将struct.pyc文件开头的内容和PZthon.pyc对比下，将开头保证一致即可。

这题的magic number并没有确实，所以不需要补充。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010111015740.png)

E3字节前面的内容就是要补充的内容。

# 0x03 反编译为py

这里使用的工具是pycdc。需要从github上clone下使用cmake编译：

[zrax/pycdc: C++ python bytecode disassembler and decompiler (github.com)](https://github.com/zrax/pycdc)

这里提供一个编译好的版本：

[cw2k/pycdc_withExe: C++ python bytecode disassembler and decompiler (github.com)](https://github.com/cw2k/pycdc_withExe)

使用方法就是

```
pycdc.exe PZthon.pyc > PZthon.py
```

即可反编译。

这题的反编译源码是：

```python
# Source Generated with Decompyle++
# File: PZthon.pyc (Python 3.9)


def hello():
    art = '\n              ___                                                                      \n    //   ) )     / /    //   ) )  // | |     / /        // | |  \\ / / \\    / /       \n   //___/ /     / /    //        //__| |    / /        //__| |   \\  /   \\  / /        \n  / ____ /     / /    //  ____  / ___  |   / /        / ___  |   / /     \\/ /         \n //           / /    //    / / //    | |  / /        //    | |  / /\\     / /          \n//           / /___ ((____/ / //     | | / /____/ / //     | | / /  \\   / /           \n                                                                                       \n     / /        //   / / ||   / / //   / /  / /       /__  ___/ ||   / |  / / //   ) ) \n    / /        //____    ||  / / //____    / /          / /     ||  /  | / / //   / /  \n   / /        / ____     || / / / ____    / /          / /      || / /||/ / //   / /   \n  / /        //          ||/ / //        / /          / /       ||/ / |  / //   / /    \n / /____/ / //____/ /    |  / //____/ / / /____/ /   / /        |  /  | / ((___/ /     \n'
    print(art)
    return bytearray(input('Please give me the flag: ').encode())

enc = [
    115,
    121,
    116,
    114,
    110,
    76,
    37,
    96,
    88,
    116,
    113,
    112,
    36,
    97,
    65,
    125,
    103,
    37,
    96,
    114,
    125,
    65,
    39,
    112,
    70,
    112,
    118,
    37,
    123,
    113,
    69,
    79,
    82,
    84,
    89,
    84,
    77,
    76,
    36,
    112,
    99,
    112,
    36,
    65,
    39,
    116,
    97,
    36,
    102,
    86,
    37,
    37,
    36,
    104]
data = hello()
for i in range(len(data)):
    data[i] = data[i] ^ 21
if bytearray(enc) == data:
    print('WOW!!')
else:
    print('I believe you can do it!')
input('To be continue...')
```

这里发现，将env的每个值异或21后打印即可。

EXP如下：

```python
enc = [115,121,116,114,110,76,37,96,88,116,113,112,36,97,65,125,103,37,96,114,125,65,39,112,70,112,118,37,123,113,69,79,82,84,89,84,77,76,36,112,99,
112,36,65,39,116,97,36,102,86,37,37,36,104]

for i in range(0,len(enc)):
    enc[i] = enc[i] ^ 21
print(bytearray(enc))
```

输出如下：

```
bytearray(b'flag{Y0uMade1tThr0ughT2eSec0ndPZGALAXY1eve1T2at1sC001}')
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/newstartctf2023-week2-reverse/  

