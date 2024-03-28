# 使用docker在x86架构上运行ARM架构的ubuntu系统


> 参考文章：[x86架构的Ubuntu上通过Docker运行ARM架构的系统-CSDN博客](https://blog.csdn.net/qq_36240047/article/details/130788137)

# 0x01 Docker安装

最简单快速的安装方法：使用阿里云镜像的一键安装脚本：

```bash
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
```

结束即安装完成。

# 0x02 使用Docker注册QEMU虚拟环境

> 每次重启宿主机均需注册（运行qemu-user-static镜像）一次

首先拉取`multiarch/qemu-user-static`镜像：

```bash
sudo docker pull --platform linux/amd64 multiarch/qemu-user-static
```

然后注册环境，即运行容器：

```bash
sudo docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

至此环境注册完成。

# 0x03 拉取Ubuntu 22.04 armv7镜像

该镜像整合了大部分运行库和gdb-mutiarch调试程序，拉取到本地：

```bash
sudo docker pull alextang223/arm-ubuntu-gdb
```

直接运行该容器即可进入arm32虚拟环境：

```bash
sudo docker run -it --rm --name arm-container --platform linux/arm/v7 alextang223/arm-ubuntu-gdb /bin/bash
```

# 0x04 环境演示

> /data文件夹存放待测试文件

![image-20231005170048844](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231005170048844.png)


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/10/%E4%BD%BF%E7%94%A8docker%E5%9C%A8x86%E6%9E%B6%E6%9E%84%E4%B8%8A%E8%BF%90%E8%A1%8Carm%E6%9E%B6%E6%9E%84%E7%9A%84ubuntu%E7%B3%BB%E7%BB%9F/  

