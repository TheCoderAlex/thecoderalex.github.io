# 彻底解决Glibc版本问题


由于不同版本的libc功能差异大，甚至无法兼容运行。同时，随意的更改系统libc版本会导致系统的崩溃。下面就Pwn有关堆利用的题目中涉及到切换libc版本的场景做出解决方案。

## 如何查看libc版本

首先，libc的动态链接文件`libc.so.6`是可执行文件，那么我们再赋予其可执行权限后可以直接运行来获得libc版本。

```bash
$ chmod +x libc.so.6
$ ./libc.so.6
# GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.
# Copyright (C) 2022 Free Software Foundation, Inc.
# This is free software; see the source for copying conditions.
# There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.
# Compiled by GNU CC version 11.2.0.
# libc ABIs: UNIQUE IFUNC ABSOLUTE
# For bug reporting instructions, please see:
# <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

可以看出上述libc的版本为2.35，是ubuntu22.04中的预装版本。

同时，通过执行系统库中的libc文件，可以获得系统libc版本。

```bash
$ /lib/x86_64-linux-gnu/libc.so.6
# GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.5) stable release version 2.35.
#Copyright (C) 2022 Free Software Foundation, Inc.
# This is free software; see the source for copying conditions.
# There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.
# Compiled by GNU CC version 11.4.0.
# libc ABIs: UNIQUE IFUNC ABSOLUTE
# For bug reporting instructions, please see:
# <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

另外，`ldd --version`也可以起到同样的效果。

```bash
$ ldd --version
# ldd (Ubuntu GLIBC 2.35-0ubuntu3.5) 2.35
# Copyright (C) 2022 Free Software Foundation, Inc.
# This is free software; see the source for copying conditions.  There is NO
# warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# Written by Roland McGrath and Ulrich Drepper.
```

## 题目给定了低版本程序

当题目使用低版本libc编译程序后，在高版本上可能无法直接运行程序。这时我们可以使用glibc-all-in-one和patchelf程序修改程序所链接的libc版本。

```bash
patchelf --set-interpreter ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-linux-x86-64.so.2 ./prog
patchelf --set-rpath ~/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ ./prog
```

首先需要使用glibc-all-in-one工具下载相应版本的libc（注意，该工具下载的编译好的libc是带debug符号的，可以直接使用gdb调试）。然后只需要使用上两行命令（不需要再更改特定lib），即可完成libc路径修改。并且此时可以直接调试程序。

## 自行编译低版本程序

如果使用Ubuntu22.04所使用的gcc版本编译程序，同时想使用patchelf将其libc版本变更为低版本，即使操作成功，运行程序时也会报错。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231212202730868.png)

至少我个人找不到从程序层面的解决办法。这时使用docker可以快速解决此类问题。

首先需要明确下各版本Ubuntu默认安装的libc版本。

+ Ubuntu22.04：libc-2.35
+ Ubuntu20.04：libc-2.31
+ Ubuntu18.04：linc-2.27
+ Ubuntu16.04：libc-2.23
+ Ubuntu14.04：libc-2.19

然后从Ubuntu的docker库中pull相应版本的image下来。例如我想要使用2.23版本的glibc，那么我需要Ubuntu16.04.

```bash
docker pull ubuntu:16.04
```

接着，在你想要的任意文件夹中，创建一个Dockerfile文件，内容如下：

```dockerfile
# 使用Ubuntu 16.04为基础镜像
FROM ubuntu:16.04

# 设置工作目录
WORKDIR /

# 安装编译工具
RUN apt-get update && \
    apt-get install -y build-essential
```

除了基础镜像的版本需要改动，其他均不需要改动，然后在该目录下构建包含gcc的image。

```bash
docker build -t ubuntu16.04-gcc .
```

ubuntu16.04-gcc是image的名称，可以自行选择。等待构建完成后，使用以下命令来创建一次性容器并进入/bin/bash：

```bash
docker run -it --rm -v $(pwd):/app -w /app ubuntu16.04-gcc /bin/bash
```

简单解释以下，-it是使用交互模式，--rm构建一次性镜像，退出即销毁。$(pwd):/app指将当前目录**挂载**到容器中的/app目录（挂载的意思是容器内部拥有可读可写权限）。-w /app是指工作目录设为/app，换句话说进入容器就跳转到/app下，ubuntu16.04-gcc是使用的image，/bin/bash是执行的程序，它为我们提供shell。

进去后，直接使用gcc编译你想要的源码，再Crtl-D退出，即可编译出一个低libc版本的C程序。

此时再使用patchelf更换libc则不会出现问题。

上面构建的image每次都可以重复使用，只需使用时创建容器即可，速度非常迅速。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/12/cglibc/  

