# NewStarCTF2023-Week1-Misc


# CyberChef's Secret

实际上是Base加密的套娃，这里根据提示使用cyberchef的magic方法

![image-20231004154018159](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004154018159.png)

直接得flag

# 机密图片

不会做。看wp得知是LSB隐写。关于LSB隐写可以参考：[浅谈LSB隐写解题与出题 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/461716971)

使用Stegsolve工具打开图片，然后发现rgb的通道0都有额外数据：

![image-20231004154417368](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004154417368.png)

于是使用data extract，选中RGB的第0通道，发现flag：

![image-20231004154522891](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004154522891.png)

# 流量！鲨鱼！

之前没有做过流量分析的题目，正好用这题入门一下。

首先使用WireShark打开流量文件，发现流量很大

![image-20231004160257467](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004160257467.png)

我们首先从http看起，发现其中有很多对目录的请求，而且基本上是404

![image-20231004160355884](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004160355884.png)

这里我们猜测实际上是一个目录爆破的过程，那么我们需要筛掉不成功的响应，这里使用

```
http && http.response.code == 200
```

![image-20231004160556582](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004160556582.png)

这里我们发现，其中有很多一样长度的文件，内容都是提示system不能执行一个空白的命令，说明这个是一个RCE的流量。在文件中还发现攻击者希望结果以base64结构输出。这里直接找最短的包，最终发现这个请求：

![image-20231004160856067](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004160856067.png)

很像是base加密，于是放到cyberchef中，发现是两次base加密：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004160945210.png)

得到flag。

# 压缩包们

提示是压缩包，先用010打开：

![image-20231004163208240](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004163208240.png)

发现是flag.zip。但是发现文件头不对，改为50 4B 03 04(pk)。然后将后缀改为zip解压：

![image-20231004163428599](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004163428599.png)

这里发现需要密码，看看压缩包属性：

![image-20231004163617345](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004163617345.png)

没看到什么信息。

回去010，发现尾部有些信息：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004163714155.png)

疑似是base加密，解密后发现：

![image-20231004163824571](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004163824571.png)

那么直接6位数字爆破即可：

![image-20231004164718039](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004164718039.png)

（这里使用的是Ziperello进行破解，ARCHPR无法破解，不知道为什么）

打开文本发现flag：

flag{y0u_ar3_the_m4ter_of_z1111ppp_606a4adc}

# 空白格

根据题目提示，应该是WriteSpace解密：

![image-20231004165103115](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004165103115.png)

![image-20231004165211860](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004165211860.png)

解密网站：[Whitelips the Esoteric Language IDE (vii5ard.github.io)](https://vii5ard.github.io/whitespace/)

# 隐秘的眼镜

SilentEye加密，直接使用工具解密：

![image-20231004165842625](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231004165842625.png)

补完收工。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/newstarctf2023-week1-misc/  

