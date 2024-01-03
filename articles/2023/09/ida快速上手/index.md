# IDA快速上手


## 快速找到程序入口

当函数列表中找不到main时，在Exports导出表中找到start入口。

![start](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230918083039907.png)

## 显示每条指令的字节码

Options-General-Disassembly

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230918083227155.png)

效果：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20230918083331039.png)

## 折叠长段变量声明

右键，Collapse declarations

## 重命名变量

右键，Rename（N）

## 查看交叉引用

右键，Jump to xref（X）

## 创建新结构体

View-Open subviews-Local types（Shift+F1）

右键Insert（Insert），按照C语法创建结构体。

对变量右键Set lvar type即可改变该变量的类型。

## 将数字转化为字符（ascii）

右键-Char或者R键

## 常见枚举（Enum）

右键-Enum

可以查看常见的枚举类型（比如EOF）

## 重新定义函数

右键undef（u释放定义）

## 标记为已处理完

右键-Mark As DeCompiled



持续更新…………


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/ida%E5%BF%AB%E9%80%9F%E4%B8%8A%E6%89%8B/  

