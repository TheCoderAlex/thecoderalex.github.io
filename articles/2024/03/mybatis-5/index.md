# 使用Mybatis的注解系统


## 使用注解开发

Mybatis支持直接在方法上使用注解添加SQL语句从而完成数据库和对象的映射。使用XML进行映射器编写时，需要现在XML中定义映射规则和SQL语句，然后再将其绑定到一个接口的方法定义上，然后再使用接口来执行：

于是就从原来的XML方式

```xml
<insert id="addStudent">
    insert into student(id, name, sex) values (#{id}, #{name}, #{sex})
</insert>
```

转变为了现在的注解方式

```java
@Insert("insert into student(id, name, sex) values (#{id}, #{name}, #{sex})")
int addStudent(Student student);
```

这个看起来就非常简洁明了了。其他的增删改查的标签在Mybatis中均有注解替代：

```java
@Select("select * from student where id = #{sid}")
Student getStudentBySid(int sid);
```

> Java中的注解可以使用反射机制获取到添加注解的方法或者类，因此无需再添加`id`进行绑定

在使用之前，需要将`mybatis-config.xml`中关于`mapper`的地址改为类：

```xml
<mappers>
    <mapper class="com.mappers.TestMapper"/>
</mappers>
```

当然，如果一个软件包下面有很多个`mapper`，可以使用`package`属性将其一次性全部导入：

```xml
<mappers>
    <package name="com.test.mapper"/>
</mappers>
```

为了实现自定义映射，可以使用`@Results`和`@Result`注解实现一一映射：

```java
@Results({
    @Result(id = true, column = "id", property = "id"),
    @Result(column = "name", property = "name"),
    @Result(column = "id", property = "studentList", many =
            @Many(select = "getStudentByTid")
           )
})
@Select("select * from teacher where id = #{tid}")
Teacher getTeacherByTid(int tid);
```

在`@Select`注解上添加`@Results`注解，并在其中添加多个`@Result`成员来实现注解的一一对应的映射。

这里的`@Many`也是一种注解，它将使用`select`中指定的属性完成一对多的查询。同理，`@One`可以实现多对一的查询。

> 在以上内容中，对`id`和`name`的映射规则是不必要的，Mybatis可以自动根据类的成员来进行映射。但是`studentList`属性是必须要自定义映射的，Mybatis无法自动的完成这个映射。

同时，Mybatis也支持在注解中读取`xml`文件中的内容。例如，在注解中编写SQL语句，但是使用在XML文件中定义的`ResultMap`。

```java
@ResultMap("test")
@Select("select * from student")
List<Student> getAllStudent();
```

当类中没有构造函数可以构造全部参数的时候，可以使用`@ConstructorArgs`注解来指定构造方法：

```java
@ConstructorArgs({
        @Arg(column = "sid", javaType = int.class),
        @Arg(column = "name", javaType = String.class)
})
@Select("select * from student where sid = #{sid} and sex = #{sex}")
Student getStudentBySidAndSex(@Param("sid") int sid, @Param("sex") String sex);
```

当然，这里也可能出现在一个SQL语句中有多个参数的时候可以使用`@Param`注解来表示

这里还有一种特殊的情况，如果方法中有一个参数是对象类型，那么即使`@Param`也无法解决这个问题。此时可以更改SQL语句中的选项：

```java
@Insert("insert into student(sid, name, sex) values(#{sid}, #{name}, #{sex})")
int addStudent(@Param("sid") int sid, @Param("student")  Student student);
```

##  使用注解开启缓存

那么如何通过注解控制缓存机制呢？

```java
@CacheNamespace(readWrite = false)
public interface MyMapper {
    @Select("select * from student")
    @Options(useCache = false)
    List<Student> getAllStudent();
```

使用`@CacheNamespace`注解直接定义在接口上即可，然后我们可以通过使用`@Options`来控制单个操作的缓存启用。

> 在项目中的配置尽量还是使用注解

---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/03/mybatis-5/  

