# Spring基础:创建项目和Bean


### 创建第一个Spring项目

> 使用Spring框架的目的在于解耦合，而非简化代码。

Spring框架由很多模块组成：

![image-20221121233807593](https://image.itbaima.cn/markdown/2022/11/21/KT2XhuCNVmcSvi5.png)

其中最核心的框架就是：`Core Container`。 只有了解了Spring的核心技术，我们才能真正认识这个框架为我们带来的便捷之处。

Spring是一个非入侵式的框架，就像一个工具库一样，它可以很简单地加入到我们已有的项目中，因此，我们只需要直接导入其依赖就可以使用了，Spring核心框架的Maven依赖坐标：

```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context</artifactId>
    <version>6.0.10</version>
</dependency>
```

> Spring 6要求Java的版本在`17`及以上，另外在SpringMVC中，要求Tomcat的版本在`10`及以上。

![image-20221122133820198](https://image.itbaima.cn/markdown/2022/11/22/HszTflPavUdQKGJ.png)

这里出现的都是Spring核心相关的内容，如Beans、Core、Context、SpEL以及非常关键的AOP框架。

首先在Maven项目的`resources`文件夹下创建Spring项目的配置文件，内容如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
        https://www.springframework.org/schema/beans/spring-beans.xsd">
</beans>
```

Spring为我们提供了一个IoC容器，用于去存放我们需要使用的对象，我们可以将对象交给IoC容器进行管理，当我们需要使用对象时，就可以向IoC容器去索要，并由它来决定给我们哪一个对象。而我们如果需要使用Spring为我们提供的IoC容器，那么就需要创建一个应用程序上下文，它代表的就是IoC容器，它会负责实例化、配置和组装Bean：

```java
public static void main(String[] args) {
  	//ApplicationContext是应用程序上下文的顶层接口，它有很多种实现，这里我们先介绍第一种
  	//因为这里使用的是XML配置文件，所以说我们就使用 ClassPathXmlApplicationContext 这个实现类
    ApplicationContext context = new ClassPathXmlApplicationContext("application.xml");  //这里写上刚刚的名字
}
```

此时，我们用之前使用过的例子实现一个`Service`接口：

```java
package org.alextang.service;

public interface Service {
}

```

然后，为该接口实现两个类：

```java
package org.alextang.service;

public class ServiceA implements Service{
}
```

```java
package org.alextang.service;

public class ServiceB implements Service{
}
```

接下来，我们就可以在Spring的配置文件中配置Bean了：

```java
<bean name="ServiceA" class="org.alextang.service.ServiceA"/>
```

Bean的`name`属性不是必须的。但是配置完成之后，就可以使用Bean的`name`来在IoC容器中`getBean`了。如果不配置，同样可以使用类的名称来`getBean`。

接下来，我们在不实例化的情况下，让IoC容器为我们实例化一个`Service`的实现：

```java
package org.alextang;

import org.alextang.service.Service;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class Main {
    public static void main(String[] args) {
        ApplicationContext context = new ClassPathXmlApplicationContext("application.xml");
        Service service = context.getBean(Service.class);
        System.out.println(service);
    }
}
```

运行，即可发现我们确实拿到了Bean中配置的类的实例：

```java
org.alextang.service.ServiceA@123f1134

进程已结束，退出代码为 0
```

此时，只需要通过更改配置文件中的内容，即可在不改变主函数代码的情况下更换拿到的实例。

```java
...
    <bean name="ServiceB" class="org.alextang.service.ServiceB"/>
</beans>
```

再次运行主函数：

```java
org.alextang.service.ServiceB@123f1134

进程已结束，退出代码为 0
```

同时，我们也可以使用定义的`name`拿到实例，但是注意需要强制转换。

```java
package org.alextang;

import org.alextang.service.Service;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class Main {
    public static void main(String[] args) {
        ApplicationContext context = new ClassPathXmlApplicationContext("application.xml");
        Service service = context.getBean(Service.class);
        Service service1 = (Service) context.getBean("ServiceB");
        System.out.println(service);
        System.out.println(service1);
    }
}
```

```java
org.alextang.service.ServiceB@123f1134
org.alextang.service.ServiceB@123f1134

进程已结束，退出代码为 0
```

> 实际上，这里得到的Student对象是由Spring通过反射机制帮助我们创建的。在高耦合度的软件开发中，我们才能体会到IoC容器管理的便捷之处。

![image-20221122153946251](https://image.itbaima.cn/markdown/2022/11/22/sjLiFokU1f3CvH5.png)

### Bean的创建和配置

注意，IoC容器使用的默认模式是单例模式，无论对类进行多少次`getBean`，拿到的都是一个实例。当然可以在Spring配置中修改设计模式。

```xml
...
<bean name="ServiceB" class="org.alextang.service.ServiceB" scope="prototype"/>
...
```

`prototype`为原型模式，`singleto`为单例模式。同时，在单例模式下，默认的配置中在容器加载配置的时候就会创建Bean的对象。无论只有需不需要这个对象，该对象都会一直存在，直到容器结束后销毁。而原型模式则是在使用的时候才会创建该对象。

当然，如果我们不想让单例模式中直接加载Bean，可以打开单例模式的懒加载模式

```xml
...
<bean name="ServiceB" class="org.alextang.service.ServiceB" lazy-init="true"/>
...
```


---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/04/spring-test/  

