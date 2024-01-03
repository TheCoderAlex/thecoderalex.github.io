# Fastbin Attack


## 关于Fastbin机制

在Glibc 2.25及之前的版本中，如果free的chunk大小小于`get_max_fast()`，也就是全局变量`global_max_fast`的值，那么他就会被放入Fastbin的链表中。前面说过，Fastbin实际上是一个单链表，它通过free chunk的fd指针来链接chunks。每当有新的chunk加入Fastbin，Fastbin就会将此chunk插入链表的开头。这里我们看下free函数中有关Fastbin的部分：

```c
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
			  <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might have let to a false positive.  Redo the test
	   after getting the lock.  */
	if (have_lock
	    || ({ assert (locked == 0);
		  __libc_lock_lock (av->mutex);
		  locked = 1;
		  chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
	if (! have_lock)
	  {
	    __libc_lock_unlock (av->mutex);
	    locked = 0;
	  }
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
	/* Check that the top of the bin is not the record we are going to add
	   (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
	  }
	/* Check that size of fastbin chunk at the top is the same as
	   size of the chunk that we are adding.  We can dereference OLD
	   only if we have the lock, otherwise it might have already been
	   deallocated.  See use of OLD_IDX below for the actual check.  */
	if (have_lock && old != NULL)
	  old_idx = fastbin_index(chunksize(old));
	p->fd = old2 = old;
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
	errstr = "invalid fastbin entry (free)";
	goto errout;
      }
  }
```

这里需要注意的是以下几点：

+ 在插入链表前首先要计算`idx`。由于Fastbin不只有一个链，不同大小的chunk会放在不同的链上。
+ 45行开始，free会检查Fastbin链表的首元素。如果本次释放的仍然是这个元素，那么就会throw double free的错误。但是由于free只检查首元素，那么存在于链表后部的chunk是否被double free是检查不出来的。

接着来看malloc部分有关Fastbin的内容，即如果用户malloc的大小不超过`global_max_fast`的值，那么就直接从Fastbin中取一块符合要求的chunk返回。

```c
/*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

这里安全性检查的部分只有一个地方，22行。当取出该chunk之前，会首先检查该chunk的size部分是不是和它所存放在的fastbin链表的idx值相同。假如说取出的是0x30的chunk，那么改chunk的size区域的8byte的值也必须是0x30（当然实际情况应该是0x31，因为有AMP三位的存在。但是`chunksize()`函数会忽略掉低三位）。

根据上面的源码分析，我们可以发现Fastbin机制对chunk的安全性检查并不是很多。所以，我们可以利用以下缺陷进行漏利用。

## 修改fd指针

### Heap Overflow

由于malloc的一块区域很可能是程序上次free的，同时free了之后并不会清空chunk的data。那么如果出现了heap overflow，

并且fastbin已经成链的情况下，我们可以通过覆写free chunk的fd的数据，来将我们想要的内存区域放入Fastbin中，然后再malloc取出想要的内存区域进行读写。下面是Nu1L Book中的一个简单例子：

```c
/*Glibc 2.23*/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

typedef struct animal {
    char desc[0x8];
    size_t lifetime;
}Animal;

void main() {
    Animal *A = malloc(sizeof(Animal));
    Animal *B = malloc(sizeof(Animal));
    Animal *C = malloc(sizeof(Animal));

    char *target = malloc(0x10);
    memcpy(target,"THIS IS A SECRET", 0x10);

    malloc(0x80);
    free(C);
    free(B);

    char *payload = "AAAAAAAAAAAAAAAAAAAAAAAA\x21\x00\x00\x00\x00\x00\x00\x00\x60";
    memcpy(A->desc, payload, 0x21);
    Animal *D = malloc(sizeof(Animal));
    Animal *E = malloc(sizeof(Animal));
    write(1,E->desc,0x10);
}
```

由于是演示代码，那就一边调试一边看好了。我们首先先将前面的四个malloc过掉，看下目前heap的结构：

![heap](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231212205338151.png)

自上而下3个0x20的chunk就是我们malloc 的三个。0x602060的chunk是target块。我们接着向下，向target内写入0x10个字符：

![heap](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231212205641175.png)

写入成功，到此时也没有什么问题。接下来还有一个malloc(0x80)，和两个free，我们直接过掉free，再次看看bins和heap的结构：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231212205923591.png)

此时fastbin是由B指向C的，因为先释放的C。同时heap中的B、C变成了free chunk。接下来，我们对A chunk（0x602000）进行overflow，试图修改已经free掉的B chunk的fd指针。为了满足安全性检测，我们不能改变B chunk中size的值。于是，payload如下：

```c
char *payload = "AAAAAAAAAAAAAAAAAAAAAAAA\x21\x00\x00\x00\x00\x00\x00\x00\x60";
```

写入后的效果为：

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231212210817331.png)

我们通过修改B chunk fd的低位地址0x20至0x60，可以将bins的链表改为B指向target。而由于C从fastbin中解链，自然变为了Allocated chunk。此时，我们只需要malloc两次，便可以获得target chunk，也就是0x602060这片区域。

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20231212211331710.png)

最后一次malloc也是成功返回了target chunk的data部分并且输出了target chunk中的内容。

### 修改fd指针低位

由于系统ASLR的限制，想要对某一块内存进行修改，必须知道目标内存的地址，这往往需要其他漏洞来泄露内存。但是堆的分配在系统中的偏移是固定的，分配的堆内存地址相对于堆内存的基地址是固定的。因此，我们只需要修改free chunk中fd指针的低位就可以指向我们想要的chunk，不需要进行信息泄露就可以进行内存的Overlap攻击。

### Double Free

即使Ptmalloc2会检查Fastbin的第一个chunk是否是当前被free的chunk，从而来检查是否存在double free。但是它并不检查fastbin中的其它chunk。那么就可以先free另一个chunk，再进行double free就不会被检查到。假如此时我们释放了A，再释放了B，接着释放A，则可以得到A->B->A->B……这样一个无限循环的链表。那么此时如果malloc一个相同大小的chunk，就会得到一个“既死又活”的A chunk。那么我们对malloc的块进行修改，就可以同时改掉fastbin的链，让A指向我们想要覆写的区块，然后再malloc2次获得此区块。该部分演示见 [how2heap-Fastbin dup](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/fastbin_dup.c)，这里不再演示。

### 改写Global Max Fast

由于arena的位置在glibc的bss段	我们可以通过改写全局变数Global Max Fast的值，处理特定大小的chunk，进而可以在arena往后的任意地址写入一个堆地址。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/12/fastbin_attack/  

