# WP-SUSCTF招新题目-Misc


## 0x01题目

题目是一个二维码

![题目](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/8e0b08f8bb34a34ff6487d87c1f77749.png)

## 0x02 分析

扫码后发现二维码包含的信息如下：

```text
\u58eb\u4eba\u0020\u5927\u571f\u0020\u5927\u4eba\u0020\u4e2d\u53e3\u0020\u4e2d\u4eba\u0020\u4eba\u5de5\u0020\u592b\u7f8a\u0020\u4e2d\u7530\u0020\u592b\u592b\u0020\u4eba\u4eba\u0020\u4eba\u7531\u0020\u5929\u4eba\u0020\u4eba\u53e3\u0020\u4e2d\u4eba\u0020\u738b\u5927\u0020\u4e2d\u53e3\u0020\u592b\u5927
```

立刻得知是Unicode编码，进行解密，得到一下中文：

![解码](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917110910.png)

```text
士人 大土 大人 中口 中人 人工 夫羊 中田 夫夫 人人 人由 天人 人口 中人 王大 中口 夫大
```

此时立刻想到是当铺密码（看到这种两个三个的汉字组合，而且这些汉字大部分都含有“口”这样的结构，就是当铺密码）。当铺密码简单来说就是汉字中“出头”的笔画个数。例如：“中”就是2，“口”和“田”都是0（没有出头），“人”是3。以此类推。

## 0x03 解密

通过Python进行自动化解密（这里面的字典可以自己添加）

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
```

最后得到：

```text
53 55 53 20 23 34 79 20 77 33 31 63 30 23 65 20 75
```

按照当铺密码的一般操作，这些数字应该代表ascii码，但是观察发现，其中20、23这些数字过小，在ASCII码中属于不可见字符，遂考虑进制转换。由于出现了79这个数字，故不可能是8进制，于是考虑16进制。于是参照以下对照表：

![ascii对照表](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917111606.png)

得到明文为：

```text
SUS #4y w31c0#e u
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/wp-susctf%E6%8B%9B%E6%96%B0%E9%A2%98%E7%9B%AE-misc/  

