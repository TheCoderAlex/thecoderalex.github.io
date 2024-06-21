# Spring基础:自动装配


### Java自动装配

当我们的类中存在其他类的成员的时候，可以使用自动装配来自动进行实例化：

```java
package org.alextang.entity.student;

import org.alextang.entity.teacher.Teacher;

public class Student {
    private Teacher teacher;
    public void hello() {
        System.out.println("Hello World!");
    }
    public void teach() {
        teacher.teach();
    }

    public void setTeacher(Teacher teacher) {
        this.teacher = teacher;
    }
}
```

使用`autowire` 的标签属性即可开启某个类的自动装配。其中分为`byType` 和`byName`的两种值。

`byType`可以根据依赖的类型找到适合的类进行实例化：

```xml
<bean name="programTeacher" class="org.alextang.entity.teacher.ProgramTeacher"/>
<bean name="Student" class="org.alextang.entity.student.ArtStudent" autowire="byType">
```

此时，`Student` 类会自动找到`org.alextang.entity.teacher.ProgramTeacher` 作为依赖注入。

如果有多个同样的类，那么这种`byType` 的方式便不再好用，此时可以使用`byName` 进行精确的定位。

> byName需要同时修改set函数的名称

```java
public class Student {
    private Teacher teacher;
    public void hello() {
        System.out.println("Hello World!");
    }
    public void teach() {
        teacher.teach();
    }

    public void setArtTeacher(Teacher teacher) {
        this.teacher = teacher;
    }
}
```

```xml
<bean name="programTeacher" class="org.alextang.entity.teacher.ProgramTeacher"/>
<bean name="artTeacher" class="org.alextang.entity.teacher.ArtTeacher"/>
<bean name="Student" class="org.alextang.entity.student.ArtStudent" autowire="byName">
```

此时就会自动寻找`org.alextang.entity.teacher.ArtTeacher` 作为依赖注入。

还可以使用`constructer` 为值进行依赖注入。此时需要指定有参的构造函数。

 ### 解决byType的冲突

当`byType` 选项拥有多个候选项的适合，可以主动排除一个候选项，使其精确选择。

使用`autowire-candidate` 设定为`false` 的适合，将排除该候选项。

```xml
<bean name="programTeacher" class="org.alextang.entity.teacher.ProgramTeacher"/>
<bean name="artTeacher" class="org.alextang.entity.teacher.ArtTeacher" autowire-candidate="false"/>
<bean name="Student" class="org.alextang.entity.student.ArtStudent" autowire="byType">
```

同时可以使用`primary="true"` 设置优先选择的一个类的实现。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/05/spring-autowire/  

