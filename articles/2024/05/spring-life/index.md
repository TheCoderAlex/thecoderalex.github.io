# Spring基础:生命周期和继承


### Bean的生命周期

除了直接修改构造函数，同时可以为Bean指定初始化方法和销毁方法，让其在对象创建和销毁的时候执行一些其他的任务：

+ `init-method` ：初始化方法
+ `destroy-method` ：销毁方法

> 注意：只有单例模式下的Bean，Spring才能完成销毁操作。如果是原型模式，则Spring无法关注其完整的生命周期。

### Bean的继承

这里的继承不是指Java中类的继承，而是对Bean的属性的继承。在两个Bean存在相似的属性时，可以直接使用继承来获得相同的属性而不用重新写。

```xml
<bean name="artStudent" class="com.test.bean.ArtStudent">
    <property name="name" value="小明"/>
</bean>
```

```xml
<bean class="com.test.bean.SportStudent">
    <property name="name" value="小明"/>
</bean>
```

对于上面的两个Bean，其中的`name` 属性的值是一致的，为了减少冗余，我们可以使用`parent` 属性进行继承。

```xml
<bean class="com.test.bean.SportStudent" parent="artStudent"/>
```

这样，在ArtStudent Bean中配置的属性，会直接继承给SportStudent Bean（注意，所有配置的属性，在子Bean中必须也要存在，并且可以进行注入，否则会出现错误）当然，如果子类中某些属性比较特殊，也可以在继承的基础上单独配置：

```xml
<bean name="artStudent" class="com.test.bean.ArtStudent" abstract="true">
    <property name="name" value="小明"/>
    <property name="id" value="1"/>
</bean>
<bean class="com.test.bean.SportStudent" parent="artStudent">
    <property name="id" value="2"/>
</bean>
```

如果我们只是希望某一个Bean仅作为一个**配置模版**供其他Bean继承使用，那么我们可以将其配置为`abstract`，这样，容器就不会创建这个Bean的对象了：

```xml
<bean name="artStudent" class="com.test.bean.ArtStudent" abstract="true">
    <property name="name" value="小明"/>
</bean>
<bean class="com.test.bean.SportStudent" parent="artStudent"/>
```

> 注意，一旦声明为抽象Bean，那么就无法通过容器获取到其实例化对象了。

另外，如果我们希望整个上下文中所有的Bean都采用某种配置，我们可以在最外层的beans标签中进行默认配置：

![](https://image.itbaima.cn/markdown/2022/11/23/KzSUJXa4jBfO9rd.png)

+ `default-init-method` 默认初始化方法
+ `default-lazy-init` 是否默认懒加载
+ ……



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/05/spring-life/  

