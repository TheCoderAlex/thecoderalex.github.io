# xctf-666-Reverse


## 0x01 查壳/脱壳

使用Die工具，发现是64位ELF，无壳。

![查壳](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917210240.png)

## 0x01 反编译

IDA64反编译结果如下，我们直接进入含有“flag{This_1s_f4cker_flag}”的函数：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230917210638942.png)

生成伪代码：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230917210731748.png)

这时发现flag{This_1s_f4cker_flag}显然是假的，而且根据以上的信息，我们要让s==enflag，而且s是和输入一起进行encode后得到的字符串。同时输入的字符串大小应该等于key，查看数据：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230917211226301.png)

发现s经过处理后应该等于izwhroz""w"v.K".Ni，key=18。

## 0x02 进入encode

ecode函数的实现如下：

```c
int __fastcall encode(const char *a1, __int64 a2)
{
  char v3[104]; // [rsp+10h] [rbp-70h]
  int v4; // [rsp+78h] [rbp-8h]
  int i; // [rsp+7Ch] [rbp-4h]

  i = 0;
  v4 = 0;
  if ( strlen(a1) != key )
    return puts("Your Length is Wrong");
  for ( i = 0; i < key; i += 3 )
  {
    v3[i + 64] = key ^ (a1[i] + 6);
    v3[i + 33] = (a1[i + 1] - 6) ^ key;
    v3[i + 2] = a1[i + 2] ^ 6 ^ key;
    *(_BYTE *)(a2 + i) = v3[i + 64];
    *(_BYTE *)(a2 + i + 1LL) = v3[i + 33];
    *(_BYTE *)(a2 + i + 2LL) = v3[i + 2];
  }
  return a2;
}
```

通过阅读发现：a1其实就是要解的flag，a2是s字符串。我们此时要假定a2=izwhroz""w"v.K".Ni然后反解出a1来。

关键在于for循环，虽然其中很多代码，但是我们发现，其实v3数组只是一个中间量，而且它的值是通过计算得出的，那么我们此时可以将等号连接起来，建立起a1和a2之间直接的联系：

```c++
*(_BYTE *)(a2 + i) = v3[i + 64] = key ^ (a1[i] + 6);
*(_BYTE *)(a2 + i + 1LL) = v3[i + 33] = (a1[i + 1] - 6) ^ key;
*(_BYTE *)(a2 + i + 2LL) = v3[i + 2] = a1[i + 2] ^ 6 ^ key;
```

继续简化：

```c++
*(_BYTE *)(a2 + i) = key ^ (a1[i] + 6);
*(_BYTE *)(a2 + i + 1LL) = (a1[i + 1] - 6) ^ key;
*(_BYTE *)(a2 + i + 2LL) = a1[i + 2] ^ 6 ^ key;
```

其中，i = 0 to 18 step 3；而a2实际上要等于izwhroz""w"v.K".N。那么根据异或的性质，a = b ^ c则有b = a ^ c （由于c ^ c = 0，且0^x = x，那么两边同时异或c即可得到）,我们可以反解出a1：

```c++
a1[i] = a2[i] ^ key - 6;
a1[i + 1] = a2[i + 1] ^ key + 6;
a1[i + 2] = a2[i + 2] ^ 6 ^ key;
```

那么构造循环即可解出。下面给出C++代码。

## 0x03 Payload

```c++
#include <iostream>
#include <string>
using namespace std;

string s = "izwhroz\"\"w\"v.K\".Ni";
char a1[18];
int main() {
    for (int i = 0;i < 18;i += 3) {
       a1[i] = (s[i] ^ 18) - 6;
       a1[i + 1] = (s[i + 1] ^ 18) + 6;
       a1[i + 2] = (s[i + 2] ^ 6 ^ 18);
    }
    for (auto i : a1){
        cout << i;
    }
    return 0;
}
```

得到答案：

![flag](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230917212215791.png)


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/xctf-666-reverse/  

