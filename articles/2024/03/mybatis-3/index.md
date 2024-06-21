# 使用Mybatis进行复杂查询


## Mybatis进行复杂查询

要将一个查询映射为一个具有多个复杂属性的类对象的时候，建议使用`resultMap`将数据库的字段和类的属性进行手动的对应。例如我们要查询下面的内容以便收集对应老师和学生的信息：

```mysql
select student.id, student.name, student.sex, teacher.id, teacher.name from student 
inner join teach on teach.sid = student.id 
inner join teacher on teach.tid = teacher.id where teacher.id = 11238
```

而我们`Teacher`类的定义如下：

```java
@Data
public class Teacher {
    int id;
    String name;
    List<Student> studentList;
}
```

于是我们可以使用以下的`resultMap`将其和数据表对应起来：

```xml
<select id="selectTeacherById" resultMap="getTeacher">
    select student.id as sid, student.name as sname, student.sex, teacher.id as tid, teacher.name as tname from student
    inner join teach on teach.sid = student.id
    inner join teacher on teach.tid = teacher.id where teacher.id = #{id}
</select>

<resultMap id="getTeacher" type="com.entity.Teacher">
    <id column="tid" property="id"/>
    <result column="tname" property="name"/>
    <collection property="studentList" ofType="com.entity.Student">
        <id column="sid" property="id"/>
        <result column="sname"   property="name"/>
        <result column="sex"    property="sex"/>
    </collection>
</resultMap>
```

对一些配置内容做出解释：

+ `constructor` - 用于在实例化类时，注入结果到构造方法中、
  + `idArg` - ID 参数；标记出作为 ID 的结果可以帮助提高整体性能
  + `arg` - 将被注入到构造方法的一个普通结果
+ `id` – 一个 ID 结果；标记出作为 ID 的结果可以帮助提高整体性能
+ `result` – 注入到字段或 JavaBean 属性的普通结果
+ `association` – 一个复杂类型的关联；许多结果将包装成这种类型
  + 嵌套结果映射 – 关联可以是 `resultMap` 元素，或是对其它结果映射的引用
+ `collection` – 一个复杂类型的集合
  + 嵌套结果映射 – 集合可以是 `resultMap` 元素，或是对其它结果映射的引用
+ `discriminator` – 使用结果值来决定使用哪个`resultMap`
+ `case` – 基于某些值的结果映射
  + 嵌套结果映射 – `case` 也是一个结果映射，因此具有相同的结构和元素；或者引用其它的结果映射

> **id & result**: 这些元素是结果映射的基础。id 和 result 元素都将一个列的值映射到一个简单数据类型（String, int, double, Date 等）的属性或字段。这两者之间的唯一不同是，id 元素对应的属性会被标记为对象的标识符，在比较对象实例时使用。 这样可以提高整体的性能，尤其是进行缓存和嵌套结果映射（也就是连接映射）的时候。

> 注意在使用`resultMap`进行映射的时候，尽量不要定义额外的构造函数。

了解了一对多，那么多对一又该如何查询呢，比如每个学生都有一个对应的老师，现在Student新增了一个Teacher对象，那么现在又该如何去处理呢？

```java
@Data
@Accessors(chain = true)
public class Student {
    private int sid;
    private String name;
    private String sex;
    private Teacher teacher;
}

@Data
public class Teacher {
    int tid;
    String name;
}
```

现在我们希望的是，每次查询到一个Student对象时都带上它的老师，同样的，我们也可以使用`resultMap`来实现（先修改一下老师的类定义，不然会很麻烦）：

```xml
<resultMap id="test2" type="Student">
    <id column="sid" property="sid"/>
    <result column="name" property="name"/>
    <result column="sex" property="sex"/>
    <association property="teacher" javaType="Teacher">
        <id column="tid" property="tid"/>
        <result column="tname" property="name"/>
    </association>
</resultMap>
<select id="selectStudent" resultMap="test2">
    select *, teacher.name as tname from student left join teach on student.sid = teach.sid
                                                 left join teacher on teach.tid = teacher.tid
</select>
```

通过使用`association`进行关联，形成多对一的关系，实际上和一对多是同理的，都是对查询结果的一种处理方式罢了。

> 更多关于**结果映射**的文档参考：https://mybatis.org/mybatis-3/zh_CN/sqlmap-xml.html

## 事务操作

可以在获取`SqlSession`关闭自动提交来开启事务模式，和JDBC其实都差不多：

```java
public static void main(String[] args) {
    try (SqlSession sqlSession = MybatisUtil.getSession(false)){
        TestMapper testMapper = sqlSession.getMapper(TestMapper.class);

        testMapper.addStudent(new Student().setSex("男").setName("小王"));

        testMapper.selectStudent().forEach(System.out::println);
    }
}
```

在关闭自动提交后内容是没有进入到数据库的，只有提交事务后才能将相应的改变写入数据库：

```java
sqlSession.commit();
```

同理，可以通过回滚操作让`commit()`之前的操作全部取消。

```java
try (SqlSession sqlSession = MybatisUtil.getSession(false)){
    TestMapper testMapper = sqlSession.getMapper(TestMapper.class);

    testMapper.addStudent(new Student().setSex("男").setName("小王"));

    testMapper.selectStudent().forEach(System.out::println);
    sqlSession.rollback();
    sqlSession.commit();
}
```

## 动态SQL

> 官方文档：https://mybatis.org/mybatis-3/zh_CN/dynamic-sql.html

在XML配置中，可以配置当满足某个条件的时候增加某个SQL条件，此时就可以使用动态SQL的语法。

```xml
<select id="selectStudentById" resultType="com.entity.Student">
    select * from student where id = #{id}
    <if test="sid % 2 == 0">
        and sex = '男'
    </if>
</select>
```

在添加以上标签后，当`sid`为偶数的时候，只能查到男生的信息。

> `test`属性的语句是Java语句

同时，还有很多动态标签的例子，例如：

```xml
<select id="findActiveBlogLike"
     resultType="Blog">
  SELECT * FROM BLOG WHERE state = ‘ACTIVE’
  <choose>
    <when test="title != null">
      AND title like #{title}
    </when>
    <when test="author != null and author.name != null">
      AND author_name like #{author.name}
    </when>
    <otherwise>
      AND featured = 1
    </otherwise>
  </choose>
</select>
```

`<when>`和`<choose>`标签就非常像Java中的`switch`和`case`的组合。

---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/03/mybatis-3/  

