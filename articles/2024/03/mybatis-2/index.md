# 使用Mybatis进行增删改查


## 使用Mybatis进行增删查改

如果在返回类型不喜欢实体类，同样可以将`resultType`改为Map：

```xml
<select id="selectStudent" resultType="Map">
    select * from student
</select>
```

```java
public interface TestMapper {
    List<Map> selectStudent();
}
```

在默认的实体类映射中，类中的字段和数据库中的字段必须保持一致。如果不想保持一致可以使用以下方法进行对应：

```xml
<resultMap id="Test" type="Student">
    <result column="sid" property="sid"/>
    <result column="sex" property="name"/>
    <result column="name" property="sex"/>
</resultMap>
```

当类中有多个构造函数的时候，需要指定使用何种`constructor`来进行对象的构造：

```java
<resultMap id="test" type="Student">
    <constructor>
        <arg column="sid" javaType="Integer"/>
        <arg column="name" javaType="String"/>
    </constructor>
</resultMap>
```

  ### 条件查询

只需要在原来的`select`块中新增`parameterType`即可（好像不加也可以）。然后在需要查询的条件上加入`#{}`即可。

> 我们通过使用`#{xxx}`或是`${xxx}`来填入我们给定的属性，实际上Mybatis本质也是通过`PreparedStatement`首先进行一次预编译，有效地防止SQL注入问题，但是如果使用`${xxx}`就不再是通过预编译，而是直接传值，因此我们一般都使用`#{xxx}`来进行操作。

```java
<select id="selectStudentById" resultType="com.entity.Student">
    select * from student where id = #{id}
</select>
```

同时在接口中新增方法，不再需要放在`List`里面，直接返回实体类即可。这里注意要在方法中加入参数。

```java
Student selectStudentById(int id);
```

此时在原来`getMapper`的基础上使用`testMapper.selectStudentById(id)`方法即可进行条件查询

```java
TestMapper testMapper = session.getMapper(TestMapper.class);
testMapper.selectStudent().forEach(System.out::println);
System.out.println("Searching id with 235297...");
System.out.println(testMapper.selectStudentById(235297));
```

### 插入数据

同样的道理，使用`<insert>`标签进行数据的插入：

```java
<insert id="addStudent">
    insert student(id, name, sex) value(#{id}, #{name}, #{sex})
</insert>
```

由于不需要返回对象，这里不用写任何的返回值类型。但是注意这里同样会返回一个`int`值。

然后在接口中定义一个和`id`相同的方法，调用即可。

```java
int addStudent(@Param("id") int id, @Param("name") String name, @Param("sex") String sex);
```

```java
System.out.println("Insert new student...");
Student tmp = new Student(235299,"小刚", "男");
System.out.println(testMapper.addStudent(tmp.getId(), tmp.getName(), tmp.getSex()));
```

> 当映射的方法参数超过一个的时候，**强烈建议使用@Param注解将方法中的参数和Mapper中的SQL语句的参数对应起来**，不然可能出现莫名奇妙的错误。

### 删除数据

同理，先定义`<delete>`标签，然后在接口中编写对应的函数即可：

```java
<delete id="deleteStudent">
    delete from student where id = #{id}
</delete>
```

```java
int deleteStudent(int id);
```

接着使用即可：

```java
System.out.println("Delete the new student...");
System.out.println(testMapper.deleteStudent(235299));
```

> 将Mapper绑定到接口后，Mybaits的优势就展现出来了，可以非常方便的调用自定义的接口方法来实现对数据库统一的操作。



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/03/mybatis-2/  

