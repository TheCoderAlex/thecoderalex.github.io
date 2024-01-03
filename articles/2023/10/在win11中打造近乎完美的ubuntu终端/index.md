# 在Win11中打造近乎完美的Ubuntu终端


# 概述

先上效果图：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231007224741313.png)

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231007224528349.png)

首先讲一下大概的配置流程：

+ 安装WSL2，也就是Windows下的linux子系统，默认安装Ubuntu 22.04
+ 安装zsh终端，和oh-my-zsh配置文件。
+ 为了保证显示效果，安装powerline字体
+ 安装Tmux终端复用工具，提升终端的工作效率
+ 安装Tmux插件和主题，进行美化

上述步骤完成即可达到上图效果。

# 安装WSL2

现在的Win11（家庭版 版本10.0.22621 版本 22621）可以一条命令安装wsl2 + Ubuntu 22.04 LTS，无需其他任何操作。

```powershell
wsl --install
```

等待安装、下载完重启即可。

重启后打开终端，下拉框选择Ubuntu，此时就会安装Ubuntu系统。期间会让你输入用户名和密码，这个就是你日后正常使用的用户。设置完则安装完成。

## 配置镜像源

首先打开文件/etc/apt/sources.list

```bash
sudo vim /etc/apt/sources.list
```

将原有没有注释（#）的语句全部注释，打开清华源官网：[ubuntu | 镜像站使用帮助 | 清华大学开源软件镜像站 | Tsinghua Open Source Mirror](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/)

确定版本后，将文本框中的内容复制粘贴到终端中（右键粘贴），保存，更新软件源：

```bash
sudo apt-get update
```

## 设置代理

因为windows中的代理不能应用于WSL，需要单独为linux设置代理，原理是利用http_proxy的变量。脚本如下：

```shell
#!/bin/sh
hostip=$(cat /etc/resolv.conf | grep nameserver | awk '{ print $2 }')
wslip=$(hostname -I | awk '{print $1}')
port=7890
 
PROXY_HTTP="http://${hostip}:${port}"
PROXY_SOCKS5="socks5://${HOST_IP}:${PROXY_PORT}"
 
set_proxy(){
  export http_proxy="${PROXY_HTTP}"
  export HTTP_PROXY="${PROXY_HTTP}"
 
  export https_proxy="${PROXY_HTTP}"
  export HTTPS_proxy="${PROXY_HTTP}"
 
  export ALL_PROXY="${PROXY_SOCKS5}"
  export all_proxy=${PROXY_SOCKS5}
 
  git config --global http.https://github.com.proxy ${PROXY_HTTP}
  git config --global https.https://github.com.proxy ${PROXY_HTTP}
 
  echo "Proxy has been opened."
}
 
unset_proxy(){
  unset http_proxy
  unset HTTP_PROXY
  unset https_proxy
  unset HTTPS_PROXY
  unset ALL_PROXY
  unset all_proxy
  git config --global --unset http.https://github.com.proxy
  git config --global --unset https.https://github.com.proxy
 
  echo "Proxy has been closed."
}
 
test_setting(){
  echo "Host IP:" ${hostip}
  echo "WSL IP:" ${wslip}
  echo "Try to connect to Google..."
  resp=$(curl -I -s --connect-timeout 5 -m 5 -w "%{http_code}" -o /dev/null www.google.com)
  if [ ${resp} = 200 ]; then
    echo "Proxy setup succeeded!"
  else
    echo "Proxy setup failed!"
  fi
}
 
if [ "$1" = "set" ]
then
  set_proxy
 
elif [ "$1" = "unset" ]
then
  unset_proxy
 
elif [ "$1" = "test" ]
then
  test_setting
else
  echo "Unsupported arguments."
fi
```

将第四行的端口改为自己的端口（即代理软件中允许局域网访问的端口）后，保存至~/proxy.sh，操作如下：

```bash
source ~/proxy.sh set	#打开代理
source ~/proxy.sh unset	#关闭代理
source ~/proxy.sh test	#测试代理连通性
```

如果设置正确，但是测试无法连通，请参照下面两个步骤：

+ 打开控制面板-防火墙-允许应用或功能通过Windows Defender防火墙，将你的代理软件放行即可。

+ 若上述操作还不成功，退回防火墙界面，在启用或者关闭防火墙中，将公用网络关闭（不建议关闭专用网络）。

# 安装zsh和oh-my-zsh

> 安装过程请保证外部网络的连通性！

执行以下两个步骤：

```bash
sudo apt install zsh
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

安装过程中会询问是否将zsh设置为默认终端，输入y回车即可。

至此zsh安装成功。

# 安装powerline字体

在windows中安装更适用于zsh显示的字体（此步可以跳过，但是后续可能会有显示问题）

> 请保证网络连通！

以管理员身份打开powershell终端，依次输入以下步骤即可：

```powershell
git clone https://github.com/powerline/fonts.git --depth=1
cd fonts
set-executionpolicy bypass
./install.ps1	#该步骤需要等待较长时间
set-executionpolicy default
```

# 更改Windows Terminal外观

打开Terminal，在下拉栏中选择设置；在左侧栏中找到Ubuntu点击进入，下滑找到外观点击进入，选择配色方案为One Half Dark，字体为 DejaVu Sans Mono for Powerline。

> 其他字体可能导致Tmux的显示问题。

# 安装zsh主题和插件

这里推荐一主题二插件。

主题是自带的，无需下载。插件下载方法如下：

> 请保证网络连通！

+ zsh-autosuggestions（历史命令显示）

```bash
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
```

+ zsh-syntax-highlighting（高亮命令和命令检查）

```bash
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
```

然后进入.zshrc，编辑以下参数：

```shell
...
ZSH_THEME="ys"	#使用ys主题
...
plugins=(
        git
        virtualenv
        zsh-autosuggestions
        zsh-syntax-highlighting
)
```

然后重启终端或者更新.zshrc即可看到效果：

```bash
source .zshrc
```

# 解决zsh-syntax-highlighting卡顿问题

产生原因：zsh-syntax-highlighting插件会从/mnt中的windows文件系统中寻找命令，由于文件数量过于庞大而造成的卡顿。

由于没有适合的替代品，同时我们还需要使用windows中的一些应用（如vscode、docker等），这里提供一种两全其美的方法：

> 参考：[syntax highlighting is super slow in WSL2 · Issue #790 · zsh-users/zsh-syntax-highlighting (github.com)](https://github.com/zsh-users/zsh-syntax-highlighting/issues/790)

打开/etc/wsl.conf，添加以下内容：

```shell
[interop]
appendWindowsPath = false
```

然后重启wsl：

```bash
wsl --shutdown
```

接着打开.zshrc，在末尾添加上：

```shell
# .zshrc
### Windows ###
export PATH="$PATH:/mnt/c/Users/lesmo/AppData/Local/Microsoft/WindowsApps"
export PATH="$PATH:/mnt/c/Users/lesmo/AppData/Local/Programs/Microsoft VS Code/bin"
export PATH="$PATH:/mnt/c/Program Files/Docker/Docker/resources/bin"
export PATH="$PATH:/mnt/c/ProgramData/DockerDesktop/version-bin"
export PATH="$PATH:/mnt/c/WINDOWS"
```

其中用户名请根据实际更改，vscode和docker的路径请按需增加（不用可注释）。

重启终端即可解决卡顿。

至此，终端界面配置全部结束，备份下自用的配置文件：

https://www.yuque.com/a13xtang/uh7onz/cyofhr0q2tnw5g27?singleDoc#

# 安装Tmux

Tmux是非常好用的终端复用工具（效率工具），安装只需一个步骤：

```bash
sudo apt-get install tmux
```

Tmux的具体使用方法请参考：[Tmux教程 （一文就够）_LYF0816LYF的博客-CSDN博客](https://blog.csdn.net/CSSDCC/article/details/121231906)

# 安装Tmux插件

> 请保证网络连通！

下载tpm：

```bash
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

接着打开~/.tmux.conf文件（没有即创建），输入：

```shell
# Settings
set -sg escape-time 1

# List of plugins
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin "nordtheme/tmux"

# Other examples:
# set -g @plugin 'github_username/plugin_name'
# set -g @plugin 'github_username/plugin_name#branch'
# set -g @plugin 'git@github.com:user/plugin'
# set -g @plugin 'git@bitbucket.com:user/plugin'

# Initialize TMUX plugin manager (keep this line at the very bottom of tmux.conf)
run '~/.tmux/plugins/tpm/tpm'
```

保存后，输入命令：

```bash
tmux	
```

或者进入任意tmux会话，先按Crtl+b，再按I（注意这是大写的I，Caps+i！），等待片刻后提示Esc即可。

> 可能需要下载，注意网络。
>
> 使用Crtl+d可以完全退出Tmux会话

至此，享受焕然一新的终端界面吧！


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/%E5%9C%A8win11%E4%B8%AD%E6%89%93%E9%80%A0%E8%BF%91%E4%B9%8E%E5%AE%8C%E7%BE%8E%E7%9A%84ubuntu%E7%BB%88%E7%AB%AF/  

