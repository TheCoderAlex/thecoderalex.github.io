# NISACTF 2022 ReorPwn?


首先checksec：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924153420070.png)

我靠，除了栈保护都开了（RELRO：禁止GOT表写入；NX：栈不可执行；PIE：地址随机化），直觉告诉我这题不会是Pwn。

看下反编译：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924153619066.png)

> Tell me what you want to execve

这里输入了一个变量a，（这个a还是在.bss区，更不可能是栈溢出），经过fun函数处理后直接system执行了。那么现在关键就是搞清楚fun函数干了什么事情。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924154022554.png)

原来是字符串翻转啊。直接exp。

# exp

> /bin/sh 翻转为 hs/nib/

直接连服务器

```bash
nc node4.anna.nssctf.cn 28509
```

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924154253097.png)

输入`hs/nib/`,然后就getshell了

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924154801249.png)

收工

---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/re-or-pwn/  

