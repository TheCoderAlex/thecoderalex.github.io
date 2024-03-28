# Reverse入门2题

## 0x00 题目概述

[Reverse1](https://buuoj.cn/challenges#reverse1)

[Reverse2](https://buuoj.cn/challenges#reverse2)

两题具有很高的相似程度，可以放在一起练习。（这里主要以Re2为例）

## 0x01 查壳/脱壳

分析程序前的必备操作。使用Win下的Die分析：

![Die](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917173839.png)

无壳，直接进入IDA反编译

## 0x02 IDA反编译

![IDA](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917174027.png)

这两题的相似点在于起点处有很多的分支或者嵌套函数，如果直接从函数起点分析将非常复杂。这里使用Shift+f12查找关键的字符串。

![字符串列表](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917174204.png)

这里可以看到`this is the right flag!`很有可能就是flag所在处。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917174701.png)

找到位置之后，使用x找到引用该字符串的位置，tab生成伪代码，如下所示：

![注释是后加的](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917174949.png)

根据分析，我们需要找到flag究竟是什么。点击flag找到flag变量所在的内存区域：

![flag](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917175129.png)

疑似字符串`{hacking_for_fun}\0`（加上结尾的null18个字节）从1081到1092刚好18个字节，于是`flag={hacking_for_fun}`

此时再回去观察对flag的操作：

```c
for ( i = 0; i <= strlen(&flag); ++i )      // 对flag字符串进行处理
{
  if ( *(&flag + i) == 105 || *(&flag + i) == 114 )
      *(&flag + i) = 49;
}
```

这里就很简单了，就是将flag中ascii等于105（i）和114（r）的转为49（1）即可。

最终答案为`flag{hack1ng_fo1_fun}`

## 0x03 总结

这里看下Re1的题：

![Re1](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917175618.png)

![Re1](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917175712.png)

发现和re2一模一样。

这类题的关键是，主要函数隐藏较深，得使用字符串查找来寻找关键的内容所在处。逆向就得慢慢看才行。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/reverse%E5%85%A5%E9%97%A82%E9%A2%98/  

