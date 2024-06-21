# Spring基础:依赖注入


### 依赖注入

依赖注入(Dependency Injection, DI)是一种设计模式，也是Spring框架的核心概念之一。现在我们已经了解了如何注册和使用一个Bean，但是这样还远远不够，还记得我们一开始说的，消除类之间的强关联吗？比如现在有一个教师接口：

```java
public interface Teacher {
    void teach();
}
```

具体的实现有两个：

```java
public class ArtTeacher implements Teacher{
    @Override
    public void teach() {
        System.out.println("我是美术老师，我教你画画！");
    }
}
public class ProgramTeacher implements Teacher{
    @Override
    public void teach() {
        System.out.println("我是编程老师，我教你学Golang！");
    }
}
```

我们的学生一开始有一个老师教他，比如美术老师：

```java
public class Student {
    private Teacher teacher = new ArtTeacher();   
  	//在以前，如果我们需要制定哪个老师教我们，直接new创建对应的对象就可以了
    public void study(){
        teacher.teach();
    }
}
```

但是我们发现，如果美术老师不教了，现在来了一个其他的老师教学生，那么就需要去修改Student类的定义：

```java
public class Student {
    private Teacher teacher = new ProgramTeacher();
  	...
```

可以想象一下，如果现在冒出来各种各样的类都需要这样去用Teacher，那么一旦Teacher的实现发生变化，会导致我们挨个对之前用到Teacher的类进行修改，这就很难受了。

而有了依赖注入之后，Student中的Teacher成员变量，可以由IoC容器来选择一个合适的Teacher对象进行赋值，也就是说，IoC容器在创建对象时，需要将我们预先给定的属性注入到对象中，非常简单，我们可以使用`property`标签来实现，我们将bean标签展开：

```xml
<bean name="teacher" class="com.test.bean.ProgramTeacher"/>
<bean name="student" class="com.test.bean.Student">
    <property name="teacher" ref="teacher"/>
</bean>
```

同时我们还需要修改一下Student类，依赖注入要求对应的属性必须有一个set方法：

```java
public class Student {
    private Teacher teacher;
  	//要使用依赖注入，我们必须提供一个set方法（无论成员变量的访问权限是什么）命名规则依然是驼峰命名法
    public void setTeacher(Teacher teacher) {
        this.teacher = teacher;
    }
    ...
```

![image-20221122191025279](https://image.itbaima.cn/markdown/2022/11/22/wu2EYC8HToJbsva.png)

使用`property`来指定需要注入的值或是一个Bean，这里我们选择ProgramTeacher，那么在使用时，Student类中的得到的就是这个Bean的对象了：

```java
Student student = context.getBean(Student.class);
student.study();
```

![image-20221122191109690](https://image.itbaima.cn/markdown/2022/11/22/n3zYWvIoE8CrRDT.png)

可以看到，现在我们的Java代码中，没有出现任何的具体实现类信息（ArtTeacher、ProgramTeacher都没出现）取而代之的是那一堆xml配置，这样，就算我们切换老师的实现为另一个类，也不用去调整代码，只需要变动一下Bean的类型就可以：

```xml
<!--  只需要修改这里的class即可，现在改为ArtTeacher  -->
<bean name="teacher" class="com.test.bean.ArtTeacher"/>
<bean name="student" class="com.test.bean.Student">
    <property name="teacher" ref="teacher"/>
</bean>
```

这样，这个Bean的class就变成了新的类型，并且我们不需要再去调整其他位置的代码，再次启动程序：

![image-20221122191427776](https://image.itbaima.cn/markdown/2022/11/22/evKArqDYcIQPCXT.png)

通过依赖注入，是不是开始逐渐感受到Spring为我们带来的便利了？当然，依赖注入并不一定要注入其他的Bean，也可以是一个简单的值：

```java
<bean name="student" class="com.test.bean.Student">
    <property name="name" value="卢本伟"/>
</bean>
```

直接使用`value`可以直接传入一个具体值。

实际上，在很多情况下，类中的某些参数是在构造方法中就已经完成的初始化，而不是创建之后，比如：

```java
public class Student {
    private final Teacher teacher;   //构造方法中完成，所以说是一个final变量

    public Student(Teacher teacher){   //Teacher属性是在构造方法中完成的初始化
        this.teacher = teacher;
    }
  	...
```

我们前面说了，Bean实际上是由IoC容器进行创建的，但是现在我们修改了默认的无参构造，可以看到配置文件里面报错了：

![image-20221122174328107](https://image.itbaima.cn/markdown/2022/11/22/5HN8GKQywWaYvrF.png)

很明显，是因为我们修改了构造方法，IoC容器默认只会调用无参构造，所以，我们需要指明一个可以用的构造方法，我们展开bean标签，添加一个`constructor-arg`标签：

```xml
<bean name="teacher" class="com.test.bean.ArtTeacher"/>
<bean name="student" class="com.test.bean.Student">
    <constructor-arg name="teacher" ref="teacher"/>
</bean>
```

这里的`constructor-arg`就是构造方法的一个参数，这个参数可以写很多个，会自动匹配符合里面参数数量的构造方法，这里匹配的就是我们刚刚编写的需要一个参数的构造方法。

![image-20221122191427776](https://image.itbaima.cn/markdown/2022/11/22/evKArqDYcIQPCXT.png)

通过这种方式，我们也能实现依赖注入，只不过现在我们将依赖注入的时机提前到了对象构造时。

那要是出现这种情况呢？现在我们的Student类中是这样定义的：

```java
public class Student {
    private final String name;
    public Student(String name){
        System.out.println("我是一号构造方法");
        this.name = name;
    }

    public Student(int age){
        System.out.println("我是二号构造方法");
        this.name = String.valueOf(age);
    }
}
```

此时我们希望使用的是二号构造方法，那么怎么才能指定呢？有2种方式，我们可以给标签添加类型：

```xml
<constructor-arg value="1" type="int"/>
```

也可以指定为对应的参数名称：

```xml
<constructor-arg value="1" name="age"/>
```

反正只要能够保证我们指定的参数匹配到目标构造方法即可。

现在我们的类中出现了一个比较特殊的类型，它是一个集合类型：

```java
public class Student {
    private List<String> list;

    public void setList(List<String> list) {
        this.list = list;
    }
}
```

对于这种集合类型，有着特殊的支持：

```xml
<bean name="student" class="com.test.bean.Student">
  	<!--  对于集合类型，我们可以直接使用标签编辑集合的默认值  -->
    <property name="list">
        <list>
            <value>AAA</value>
            <value>BBB</value>
            <value>CCC</value>
        </list>
    </property>
</bean>
```

不仅仅是List，Map、Set这类常用集合类包括数组在内，都是支持这样编写的，比如Map类型，我们也可以使用`entry`来注入：

```xml
<bean name="student" class="com.test.bean.Student">
    <property name="map">
        <map>
            <entry key="语文" value="100.0"/>
            <entry key="数学" value="80.0"/>
            <entry key="英语" value="92.5"/>
        </map>
    </property>
</bean>
```

至此，我们就已经完成了两种依赖注入的学习：

- Setter依赖注入：通过成员属性对应的set方法完成注入。
- 构造方法依赖注入：通过构造方法完成注入。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/04/spring-injection/  

