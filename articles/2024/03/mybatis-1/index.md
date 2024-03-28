# Mybatis基本使用


## Mybatis简介

![image-20230306163528771](https://image.itbaima.cn/markdown/2023/03/06/IEhBoWbg93dZuek.png)

MyBatis 是一款优秀的持久层框架，它支持定制化 SQL、存储过程以及高级映射。MyBatis 避免了几乎所有的 JDBC 代码和手动设置参数以及获取结果集。MyBatis 可以使用简单的 XML 或注解来配置和映射原生信息，将接口和 Java 的 POJOs(Plain Ordinary Java Object,普通的 Java对象)映射成数据库中的记录。

> 封装了数据库中记录和Java对象的转换

## XML语言

XML语言发明最初是用于数据的存储和传输（写配置文件用的）。

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<outer>
  <name>阿伟</name>
  <desc>怎么又在玩电动啊</desc>
	<inner type="1">
    <age>10</age>
    <sex>男</sex>
  </inner>
</outer>
```

> HTML是为了展示文件，XML是为了储存文件

一个XML文件存在以下的格式规范：

- 必须存在一个**根节点**，将所有的子标签全部包含。
- 可以但不必须包含一个头部声明（主要是可以设定编码格式）
- 所有的标签必须**成对出现**，可以嵌套但不能交叉嵌套
- 区分**大小写**。
- 标签中可以存在属性，比如上面的`type="1"`就是`inner`标签的一个属性，属性的值由单引号或双引号包括。

XML的注释内容和HTML一样

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!-- 注释内容 -->
```

XML中存在转义字符以防止产生歧义：

![img](https://image.itbaima.cn/markdown/2023/03/06/j5WEDVxYJ8KSkHt.jpg)

使用CDATA可以快速创建不解析的区域：

```xml
<test>
    <name><![CDATA[我看你<><><>是一点都不懂哦>>>]]></name>
</test>
```

为了在Java中读取xml配置文件的信息，JDK为我们内置了一个叫做`org.w3c`的XML解析库来解析xml文件：

```java
// 创建DocumentBuilderFactory对象
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// 创建DocumentBuilder对象
try {
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document d = builder.parse("file:mappers/test.xml");
    // 每一个标签都作为一个节点
    NodeList nodeList = d.getElementsByTagName("test");  // 可能有很多个名字为test的标签
    Node rootNode = nodeList.item(0); // 获取首个

    NodeList childNodes = rootNode.getChildNodes(); // 一个节点下可能会有很多个节点，比如根节点下就囊括了所有的节点
    //节点可以是一个带有内容的标签（它内部就还有子节点），也可以是一段文本内容

    for (int i = 0; i < childNodes.getLength(); i++) {
        Node child = childNodes.item(i);
        if(child.getNodeType() == Node.ELEMENT_NODE)  //过滤换行符之类的内容，因为它们都被认为是一个文本节点
        System.out.println(child.getNodeName() + "：" +child.getFirstChild().getNodeValue());
        // 输出节点名称，也就是标签名称，以及标签内部的文本（内部的内容都是子节点，所以要获取内部的节点）
    }
} catch (Exception e) {
    e.printStackTrace();
}
```

> 目前很多框架都会使用XML来作为配置文件，主要是认识即可

## Mybatis的使用

> 中文文档网站：https://mybatis.org/mybatis-3/zh_CN/getting-started.html

首先需要创建Mybatis的配置文件，在根目录下创建`mybaits-config.xml`文件，加入官方文档中的内容：

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE configuration
  PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
  "https://mybatis.org/dtd/mybatis-3-config.dtd">
<configuration>
  <environments default="development">
    <environment id="development">
      <transactionManager type="JDBC"/>
      <dataSource type="POOLED">
        <property name="driver" value="${driver}"/>
        <property name="url" value="${url}"/>
        <property name="username" value="${username}"/>
        <property name="password" value="${password}"/>
      </dataSource>
    </environment>
  </environments>
  <mappers>
    <mapper resource="org/mybatis/example/BlogMapper.xml"/>
  </mappers>
</configuration>
```

我们需要自定义的选项是：

+ `${driver}`：改写成使用的相应的数据库的驱动
+ `${url}`：写成JDBC的连接url，可以在IDEA的数据库配置页面查询到
+ `${username}`：即数据库的用户名
+ `${password}`：即数据库的密码

> 其中mappers暂时没有用到，可以先删除掉

在Java中创建一下`SqlSessionFactory`来打开一个`SqlSession`：

```java
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;

import java.io.FileInputStream;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        FileInputStream fileInputStream = new FileInputStream("mybatis-config.xml");
        SqlSessionFactory sqlSessionFactory = new SqlSessionFactoryBuilder().build(fileInputStream);
        try (SqlSession session = sqlSessionFactory.openSession(true)) {

        }

    }
}
```

那Mybatis究竟做了什么？每个基于 MyBatis 的应用都是以一个 `SqlSessionFactory `的实例为核心的，我们可以通过`SqlSessionFactory`来创建多个新的会话，`SqlSession`对象，每个会话就相当于在不同的地方登陆一个账号去访问数据库，会话之间相互隔离，没有任何关联。

而通过`SqlSession`就可以完成几乎所有的数据库操作，我们发现这个接口中定义了大量数据库操作的方法，因此，现在我们只需要通过一个对象就能完成数据库交互了，极大简化了之前的流程。

![img](https://image.itbaima.cn/markdown/2023/03/06/67AJEFCsKoin3Hd.jpg)

接下来，为了将数据库查询结果直接返回为对象，需要实现一个`Mapper`作为数据库查询结果和Java对象的映射，内容大体如下所示：

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="TestMapper">
    <select id="selectStudent" resultType="com.entity.Student">
        select * from student
    </select>
</mapper>
```

然后在Mybatis配置文件中加入`Mapper`：

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE configuration
        PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
        "https://mybatis.org/dtd/mybatis-3-config.dtd">
<configuration>
    <environments default="development">
        <environment id="development">
            <transactionManager type="JDBC"/>
            <dataSource type="POOLED">
                <property name="driver" value="com.mysql.cj.jdbc.Driver"/>
                <property name="url" value="jdbc:mysql://localhost:3306"/>
                <property name="username" value="root"/>
                <property name="password" value="998244353"/>
            </dataSource>
        </environment>
    </environments>
    <mappers>
        <mapper url="file:TestMapper.xml"/>
    </mappers>
</configuration>
```

注意是在`configuration`的最后添加`mappers`标签。接下来直接通过`session`的`selectList`方法就可以把所有查询的结果自动转换为`Student`对象并且返回一个`List`结构中。

```java
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import com.entity.Student;

public class Main {
    public static void main(String[] args) throws IOException {
        FileInputStream fileInputStream = new FileInputStream("mybatis-config.xml");
        SqlSessionFactory sqlSessionFactory = new SqlSessionFactoryBuilder().build(fileInputStream);
        try (SqlSession session = sqlSessionFactory.openSession(true)) {
            List<Student> studentList = session.selectList("selectStudent");
            studentList.forEach(System.out::println);
        }
    }
}
```

### 优化Mybatis的使用

可以在另外一个类中集成对`SqlSessionFactory`的创建，然后每次使用的时候只需要`openSession`即可。

```java
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class MybatisUtil {
    //在类加载时就进行创建
    private static SqlSessionFactory sqlSessionFactory;
    static {
        try {
            sqlSessionFactory = new SqlSessionFactoryBuilder().build(new FileInputStream("mybatis-config.xml"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * 获取一个新的会话
     * @param autoCommit 是否开启自动提交（跟JDBC是一样的，如果不自动提交，则会变成事务操作）
     * @return SqlSession对象
     */
    public static SqlSession getSession(boolean autoCommit){
        return sqlSessionFactory.openSession(autoCommit);
    }
}
```

```java
public class Main {
    public static void main(String[] args) throws IOException {
        try (SqlSession session = MybatisUtil.getSession(true)) {
            List<Student> studentList = session.selectList("selectStudent");
            studentList.forEach(System.out::println);
        }
    }
}
```

### 使用接口方法返回对象

在之前的操作中，我们使用如下操作来获得数据库转换成为的对象：

```java
List<Student> studentList = session.selectList("selectStudent");
studentList.forEach(System.out::println);
```

在使用这个方法之前，我们必须知道：

+ mapper的ID
+ 返回值的类型
+ 对象的类型

为了隐藏上面的实现，我们可以使用接口来绑定特定的mapper和方法。我们只需要调用该方法即可获得对象的信息。首先我们定义以下接口，使得方法名称是mapper的ID：

```java
public interface TestMapper {
    List<Student> selectStudent();
}
```

接着，将mapper配置文件中的namespace绑定为该接口：

```java
<mapper namespace="com.mappers.TestMapper">
    <select id="selectStudent" resultType="com.entity.Student">
        select * from student
    </select>
</mapper>
```

接下来，我们只需要通过`sqlSession`的`getMapper`方法，即可让Mybatis自动实现`TestMapper`接口，并且调用`selectStudent()`方法来返回`List<Student>`类型。

```java
try (SqlSession session = MybatisUtil.getSession(true)) {
    TestMapper testMapper = session.getMapper(TestMapper.class);
    testMapper.selectStudent().forEach(System.out::println);
}
```

以后的开发中将使用接口来进行Sql对象的操作，从而避免使用不明确的返回类型。

### Mybatis配置解析

+ `environment`：在一个配置文件中可以创建不同的环境，每个环境都可以采用不同的数据库，这样以应对不同开发场景下的需求。
+ `transactionManager`：事务管理器，常见的即JDBC、MANAGED
+ `dataSource`：数据源。有三种内建的数据源类型（也就是 type="[UNPOOLED|POOLED|JNDI]"。
  + **POOLED**– 这种数据源的实现利用“池”的概念将 JDBC 连接对象组织起来，避免了创建新的连接实例时所必需的初始化和认证时间。 这种处理方式很流行，能使并发 Web 应用快速响应请求。

可以给类型起一个别名，简化Mapper的编写：

```java
<!-- 需要在environments的上方 -->
<typeAliases>
    <typeAlias type="com.test.entity.Student" alias="Student"/>
</typeAliases>
```

现在Mapper就可以直接使用别名了：

```xml
<mapper namespace="com.test.mapper.TestMapper">
    <select id="selectStudent" resultType="Student">
        select * from student
    </select>
</mapper>
```

如果这样还是很麻烦，我们也可以直接让Mybatis去扫描一个包，并将包下的所有类自动起别名（别名为首字母小写的类名）

```java
<typeAliases>
    <package name="com.test.entity"/>
</typeAliases>
```

也可以为指定实体类添加一个注解，来指定别名：

```java
@Data
@Alias("lbwnb")
public class Student {
    private int sid;
    private String name;
    private String sex;
}
```

不同的配置可以省略，但是相对位置不可以改变，否则就会报错。

当然，Mybatis也包含许多的基础配置，通过使用：

```xml
<settings>
    <setting name="" value=""/>
</settings>
```

所有的配置项可以在中文文档处查询，本文不会进行详细介绍，在后面我们会提出一些比较重要的配置项。



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/03/mybatis-1/  

