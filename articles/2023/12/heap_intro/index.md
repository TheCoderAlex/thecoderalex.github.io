# 堆基础


> 本节内容基于Glibc 2.25版本

## 什么是堆

堆（chunk）内存是一种允许程序在运行过程中动态分配和使用的内存区域。相比较于栈内存和全局内存，堆内存没有固定的生命周期和固定的内存区域。程序可以动态地申请和释放不同大小的内存。被分配后，如果没有进行明确的释放操作，该堆内存区域都是一直有效的。

![heapinfo](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231210103434924.png)

绿色部分就是程序申请的堆区（main_arena）。

为了进行**高效**的堆内存分配（高效往往带来安全性问题），回收和管理，Glibc实现了**Ptmalloc2**的堆管理器。下面的介绍仅基于Ptmalloc2堆管理器的实现。

在[https://elixir.bootlin.com/](https://elixir.bootlin.com/glibc/glibc-2.25/source/malloc/malloc.c)可以查看到各版本的Ptmalloc2源码，当然也包括Glibc中其他实现的源码。

## Chunk

Ptmalloc2所分配的堆的最基本结构为Chunk。首先我们需要了解一下Ptmalloc2分配堆空间的流程：

+ 程序中第一次使用malloc时初始化**main_arena**，并向Kernel申请一大块内存空间（在上图中大约为132KB）。接着从刚刚申请的heap区域切割一块区域作为malloc的返回。
+ main_arena存在于libc中，记录着有关堆的各种信息。
  + 各种bins的链表位置
  + Top chunk的地址
  + ……
+ 程序以后的malloc/free实际上都是对chunk的回收和再利用，回收和利用的途径就是main_arena中记录的bins链表。
+ 除非第一次申请的内存空间不够，否则Ptmalloc2不会再次向Kernel申请区域，因为和内核的交互太消耗时间。

不同于栈，堆的生长方向是自低地址向高地址生长。最高的地址是Top chunk，其次越先分配的chunk地址越小。

chunk在Glibc中的定义如下：

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

根据chunk的定义，普通chunk的结构大概分为chunk header和chunk data两部分，具体示意图如下：

![chunk](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231210111813463.png)

+ prev_size/data：临近的上一个Chunk的size或者data
+ size：此Chunk的size
+ A(NON_MAN_ARENA bit)：是否由其他的arena管理，而不是main_arena
+ M(IS_MMAPPED bit)：是否由mmap创造出来
+ P(PREV_INUSE bit)：临近的上一个Chunk是否正在使用

首先，prev_size/data其实就是上一个chunk的data部分（用户可以使用的区域）。但是如果上一个chunk被free了，那么就只做prev_size的用处。

malloc的内存大小实际上不等于chunk size，chunk size的计算方式如下：

```c
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```

这样已经很好理解了，就是在malloc请求的大小的基础上加上size的8byte，然后再和8byte对齐即可。举个例子：假设var = req + 8，如果var的值0x21-0x2f，则对齐为0x30，而若var=0x20则不需要对齐。

在Ptmalloc2中，总共有三种形式的Chunk，分别是Allocated Chunk，Free Chunk，Top Chunk。

+ Allocated Chunk，即正在使用的Chunk，结构如上图所示。由于inuse，它的临近的下一个chunk的P bit会被设置为1。

+ Free Chunk，即free掉的chunk，这些chunk实际上会根据不同的size进入不同的bins链表中。它的结构如下所示：其中，fd为Forward Pointer，指向下一个Free的Chunk；bk为Backward Pointer，指向上一个Free掉的Chunk。bins通过fd和bk指针维持其链表结构。

  ![Free Chunk](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231210113722793.png)

+ Top Chunk，在Heap的顶端（最高地址），代表着剩余的空间。

  ![Top Chunk](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231210114210291.png)

## Bins

为了高效的管理内存并且尽可能防止内存碎片，Ptmalloc2将不同大小的free chunk分为不同的bin结构，分别为**Fast Bin**、**Small Bin**、**Large Bin**、**Unsorted Bin**。

### Fast Bin

如果chunk被释放时发现大小满足Fast Bin的要求，即在（0x20 - 0x80）之间，则将该chunk放入Fast Bin，且放入后不修改P标志位的数值。Fast Bin以单链表的形式储存，不同大小的Fast Bin储存在对应大小的单链表结构中，其单链表的存取机制是LIFO。也就是说，新加入的chunk永远在表头的位置，指向上一个加入的chunk。

### Small Bin

Small Bin的所允许的大小更大一点，在（0x20-0x400）之间，而且放入的chunk链表为双链表结构（`fd`下一个chunk，`bk`上一个chunk），存取方式为FIFO，速度比Fast Bin稍慢一点。

### Large Bin

可以存取大于0x400字节的chunk。Large Bin的结构相对于其他Bin是最复杂的，速度也是最慢的，相同大小的Large Bin使用fd和bk指针连接，不同大小的Large Bin通过`fd_nextsize`和`bk_nextsize`按照大小排序连接。

### Unsorted Bin

Unsorted Bin是Ptmalloc2堆管理器的真正意义上的垃圾桶。chunk被释放后，会先加入Unsorted Bin，等待下次分配使用。在Unsorted Bin不为空的时候，如果Fast Bin和Small Bin中都没有合适的chunk，用户申请内存就会从Unsorted Bin中寻找，如果找到符合申请大小要求的chunk，则直接分配，或者分割该chunk。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/12/heap_intro/  

