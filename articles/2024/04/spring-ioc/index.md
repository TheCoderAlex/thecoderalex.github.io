# Spring基础:IoC理论


## IoC容器基础

Spring框架最核心的其实它的IoC容器，Spring框架使用IoC容器管理各个不同的组件。

### IoC理论介绍

在Java的应用程序开发中，程序中的各个组件都是相互耦合的。每一个组件都可能依赖着另外的一个组件。比如说：要展示借阅信息列表，那么首先需要使用`Servlet`进行请求和响应的数据处理，然后请求的数据全部交给对应的Service（业务层）来处理，当Service发现要从数据库中获取数据时，再向对应的`Mapper`发起请求。简单来说，应用程序中的各个类就像连接在一起的齿轮，谁也离不开谁。

![img](https://image.itbaima.cn/markdown/2022/10/08/YQRP2idIS5skHJ4.png)

虽然这样开发的逻辑非常清晰，但是存在一个很严重的问题。如果其中的一个模块需要更新，那么就需要去其他所有的模块中重新修改有关改部分模块的内容。这样可能会导致整个项目的重新编写。这就是项目中各个组件耦合度过高的原因。比如说下面的情况：

```java
class A{
    private List<B> list;
    public B test(B b){
        return null;
    }
}

class C{
    public C(B b){}
}

class B{ }
```

可以看到，A和C在大量地直接使用B，但是某一天，这个B的实现已经过时了，此时来了个把功能实现的更好的D，我们需要用这个新的类来完成业务了：

![image-20221122135859871](https://image.itbaima.cn/markdown/2022/11/22/FRQn6vEpTklsJKe.png)

可以看到，因为类之间的关联性太强了，会开始大面积报错，所有之前用了B的类，得挨个进行修改，全都改成D。

为了解除现代软件中耦合度过高的问题，我们只能想办法将各个模块进行解耦合。让各个模块之间的依赖性不再那么地强。换句话说，软件中某个模块的实现类不再由我们来决定，而是让软件自己来决定。这样就引入了IoC理论。

IOC是Inversion of Control的缩写，翻译为：“控制反转”，把复杂系统分解成相互合作的对象，这些对象类通过封装以后，内部实现对外部是透明的，从而降低了解决问题的复杂度，而且可以灵活地被重用和扩展。如下图所示：

![img](https://image.itbaima.cn/markdown/2022/10/08/XsYQRk93CHewISB.png)

我们可以将对象交给IoC容器进行管理，比如当我们需要一个接口的实现时，由它根据配置文件来决定到底给我们哪一个实现类，这样，我们就可以不用再关心我们要去使用哪一个实现类了，我们只需要关心，给到我的一定是一个可以正常使用的实现类，能用就完事了，反正接口定义了啥，我只管调，这样，我们就可以放心地让一个人去写视图层的代码，一个人去写业务层的代码。即使出现了迭代更新也可以很方便的修改。

> IoC理论实际上就是将项目中不变的东西抽象出来，使用不变的东西管理经常变化的东西，因此只管变就行。

如果将之前的代码改为IoC容器的版本，将是这样的（示例）：

```java
public static void main(String[] args) {
		A a = new A();
  	a.test(IoC.getBean(Service.class));   //瞎编的一个容器类，但是是那个意思
  	//比如现在在IoC容器中管理的Service的实现是B，那么我们从里面拿到的Service实现就是B
}

class A{
    private List<Service> list;   //一律使用Service，具体实现由IoC容器提供
    public Service test(Service b){
        return null;
    }
}

interface Service{ }   //使用Service做一个顶层抽象

class B implements Service{}  //B依然是具体实现类，并交给IoC容器管理
```

```java
interface Service{ }

class D implements Service{}   //现在实现类变成了D，但是之前的代码并不会报错
```

从上面的代码可以看出，无论是何种实现类实现了`Service`接口，IoC容器都可以直接调用出想要的实现类，而不需要在原来的代码中进行修改，只需要一直更新即可。

高内聚，低耦合，是现代软件的开发的设计目标，而Spring框架就给我们提供了这样的一个IoC容器进行对象的的管理，一个由Spring IoC容器实例化、组装和管理的对象，我们称其为`Bean`。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/04/spring-ioc/  

