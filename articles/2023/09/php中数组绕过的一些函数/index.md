# PHP中数组绕过的一些函数


## 简介

记录PHP可以使用数组进行绕过的一些函数，保持更新

## 0x01 md5()

```php
if (isset($_GET['a']) and isset($_GET['b'])) {
if ($_GET['a'] != $_GET['b'])
if (md5($_GET['a']) === md5($_GET['b']))
die('Flag: '.$flag);
else
print 'Wrong.';
}
```

md5处理不了数组类型的数据，将直接返回null（注意：null != false），null==null，成功绕过

```php
md5(array()) = null
```

## 0x02 strcmp()

```php
$pass=@$_POST['pass'];
$pass1=***********;//被隐藏起来的密码
if(isset($pass))
{
if(@!strcmp($pass,$pass1)){
echo "flag:nctf{*}";
}else{
echo "the pass is wrong!";
}
}else{
echo "please input pass!";
}
```

strcmp函数用于字符串的比较

```php
int strcmp ( string $str1 , string $str2 )
```

返回值：如果 `str1` 小于 `str2` 返回 < 0； 如果 `str1` 大于 `str2` 返回 > 0；如果两者相等，返回 0。

- 5.2 中是将两个参数先转换成string类型。
- 5.3.3 以后，当比较数组和字符串的时候，返回是0。
- 5.5 中如果参数不是string类型，直接return了

```php
strcmp(array(), "abc") = null
```

## 0x03 strpos()

基本同strcmp

```php
strpos(array(), "abc") = null
```

## 0x04 ereg()

ereg()有两种利用方式

+ 00截断（已被preg_match替代）
+ 已被preg_match替代

```php
ereg(pattern,array()) = null
```

## 0x05 preg_match()

```php
preg_match(pattern,array) = false
```

> preg_match()返回 `pattern` 的匹配次数。 它的值将是0次（不匹配）或1次，因为preg_match()在第一次匹配后 将会停止搜索。preg_match_all()不同于此，它会一直搜索`subject` 直到到达结尾。 如果发生错误preg_match()返回 FALSE。



---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/php%E4%B8%AD%E6%95%B0%E7%BB%84%E7%BB%95%E8%BF%87%E7%9A%84%E4%B8%80%E4%BA%9B%E5%87%BD%E6%95%B0/  

