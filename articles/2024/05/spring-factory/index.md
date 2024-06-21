# Spring基础:适配工厂设计模式


### 工厂模式和工厂Bean

如果某个类的设计模式是工厂模式，Spring将无法构造出类的实例，而是只能通过该类的`Factory` 构造方法拿到实例化的类。

此时我们可以直接使用`factory-method` 属性来制定类的构造工厂：

```xml
<bean class="com.test.bean.StudentFactory" factory-method="getStudent"/>
```

> 注意：实际上还是创建了`Student`的Bean，而不是`Factory` 的Bean
>
> 同时，通过构造工厂获得的实例无法再被Spring管理，只能通过`Factory`进行初始化等。

同时，也可以将`StudentFactory`直接注册为Bean，然后通过`StudentFactory` 的实例来获得`Student` 的实例。

```xml
<bean name="studentFactory" class="com.test.bean.StudentFactory"/>
```

 然后再使用`factory-bean`来指定Bean的工厂Bean：

```xml
<bean factory-bean="studentFactory" factory-method="getStudent"/>
```

此时获得的Bean就可以和正常的类一样进行依赖注入等操作。

这里还有一个很细节的操作，如果我们想获取工厂Bean为我们提供的Bean，可以直接输入工厂Bean的名称，这样不会得到工厂Bean的实例，而是工厂Bean生产的Bean的实例：

```java
Student bean = (Student) context.getBean("studentFactory");
```

当然，如果我们需要获取工厂类的实例，可以在名称前面添加`&`符号：

```java
StudentFactory bean = (StudentFactory) context.getBean("&studentFactory");
```

另外，如果可以修改`Factory` 类的话，可以通过实现`FactoryBean<T>` 接口的`getObject()`和`getObjectType()` 方法来直接注册为工厂。

---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/05/spring-factory/  

