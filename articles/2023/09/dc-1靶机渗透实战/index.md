# DC-1靶机渗透实战

## 0x00 DC-1介绍
DC-1是一个专门建造的易受攻击的实验室，目的是在渗透测试领域获得经验。
它旨在对初学者来说是一个挑战，但它的难易程度取决于您的技能和知识以及您的学习能力。
要成功完成这一挑战，您需要 Linux 技能、熟悉 Linux 命令行以及基本渗透测试工具的经验，例如可以在 Kali Linux 或 Parrot Security OS 上找到的工具。

有多种方法可以扎根，但是，我包括了一些包含初学者线索的标志。
总共有五个标志，但最终目标是在 root 的主目录中查找并读取该标志。您甚至不需要是 root 用户即可执行此操作，但是，您将需要 root 权限。
根据您的技能水平，您也许可以跳过查找大多数这些标志并直接进入root。
初学者可能会遇到以前从未遇到过的挑战，但谷歌搜索应该是获得完成此挑战所需的信息所需的全部内容。
下载地址：https://vulnhub.com/entry/dc-1,292/

## 0x01 信息搜集
+ 使用arp-scan扫描内网存活主机
![arp-scan](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/6cc0bcaace254fe2918d165a35deb619.png)
本机ip是128，所以130很可能是我们需要找的主机。这里可以用nmap再扫一下C段确认一下，我是直接nmap 130
+ nmap扫描主机开放端口
![nmap](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/4a4f4d50d3cd48b18bb6ba7b48f2b51c.png)
比较有用的就是22的ssh端口，可以尝试寻找密码或者爆破进入，还有80端口，一个使用Apache搭建的web服务器。
+ 查看web服务器
![查看web服务器](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/e30a98b0ee554f8bb9e8ced1d1bb3b0f.png)
发现一个登录界面，尝试几组弱口令无效。
使用dirb扫描后台地址，发现admin页面，但是未授权访问禁止。
![admin页面](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/5b2baa2c9dd34fe88d79ec6fa05c310a.png)

查看网站banner信息，发现所用CMS为Drupal7，网上查询发现Drupal7存在很多漏洞，这里就准备进入msf直接exploit。![banner](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/4f0405693ba244e49e0f559883612cce.png)
## 0x02 msf exploit
进入msfconsole，search drupal，发现确实有几个可以利用的漏洞
![msfconsole](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/fa57e4e8c2404d0a86fdf97b36748fbf.png)
这里建议根据rank选择较新的漏洞，（后来试了其他漏洞基本不可用)，选择编号为1的exploit/unix/webapp/drupal_drupalgeddon2漏洞利用。然后配置相应选项。这里的payload就使用默认的php/meterpreter/reverse_tcp。这里发现本机信息已经自动填好，填上被攻击机的ip和端口即可。即：

```bash
set rhosts 192.168.253.130
```
![msfconsole](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/b3745688b2bf4101a9d000990bfa5f37.png)

不存在代理什么的，那么填完直接利用。等待一会，攻击成功，进入meterpreter。这时干什么都行了，赶紧看看当前用户和目录下的文件。
## 0x03 后渗透

meterpreter自带的shell非常不方便，这时使用python创建一个可交互的终端
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
![bash](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/cb34b2b3990b49a0b82dd2b9ca4df022.png)
此时发现flag1，打开flag1，提示我们需要找CMS的配置文件
![可交互终端](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/ee0b31790c454a69bfc6fc66c3863977.png)
在网上搜素，发现drupal的配置文件应该在sites文件夹中的一个叫setting.php的文件中，于是查找。发现在sites/default/下有该文件，打开后发现flag2，提示我们需要获得网站权限。配置文件中有包含该网站数据库的信息，于是进入数据
库寻找网站的登录信息。
![数据库信息](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/01cda04d3cd94221a440127a949ffb49.png)
找到数据库drupaldb，表users，发现其中有两个用户，我们比较关心的是用户名和密码，于是
```sql
select uid,name,pass from users;
```
得到
![表](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/66d66583c36145438e194f73752fcbe4.png)
发现有两个用户，并且密码都是加密的，看密文中都是`$S$D`开头，不像是我们已知的常见编码形式。
上网查找，发现Drupal使用一种名为Phpass的加密算法，并且告诉我们加密的脚本位于script/password-hash.sh。这样我们可以直接修改admin的密文即可。
![密码加密算法](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/800fadd10b1446609d88632a5e583511.png)
```bash
./password-hash.sh "1234"
```
这里注意要cp一份到www目录，因为脚本需要include目录，而include在www目录。
![加密结果](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/5f7256f9cb814139b05610a46efdeca1.png)
得到密文 `$S$DGAsy9C181OKmGr.Hm.Pkf31BVLsDVMURQhoTMRDniH16ThmZsVq`

回到mysql直接更改admin的密码。
![更改密码(https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/111294999360411eb5935fa82a2411ed.png)
修改完成后直接登录后台，使用admin 1234。
![登录后台](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/74151cc217e6496a961133f93caef03d.png)
在content中发现flag3，提示我们查看shadow文件，并使用find -exec 提权。

回到终端，发现find确实有suid。
![suid程序](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/c739367082a74cc28bda9f5bbb1db9c3.png)
同时查看shadow文件，（/etc/shadow）
![查看shadow文件](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/30b6ab9cde884f50ad5a2b1dff411549.png)
不给看。那就直接提权。
```bash
find /etc/shadow -exec '/bin/sh' \;
```
![find提权](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/06c1baafe45743418825f2a10ec5d9ed.png)
提权成功。查看shadow，发现flag4用户，切换到flag4的家目录，发现flag4。
![flag4](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/995d83fa737d48a2801a8cdd9f96a37b.png)
同时提示我们第五个flag在root的家目录中，我们已经是root了，在家目录下寻找即可：
![flag5](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/0095f89ce78d4f69ac38f95da4b4aec6.png)
成功找到5个flag。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/dc-1%E9%9D%B6%E6%9C%BA%E6%B8%97%E9%80%8F%E5%AE%9E%E6%88%98/  

