# JDBC-1-基础


## JDBC简介

JDBC是什么？JDBC英文名为：Java Data Base Connectivity(Java数据库连接)，官方解释它是Java编程语言和广泛的数据库之间独立于数据库的连接标准的Java API，根本上说JDBC是一种规范，它提供的接口，一套完整的，允许便捷式访问底层数据库。可以用JAVA来写不同类型的可执行文件：JAVA应用程序、JAVA Applets、Java Servlet、JSP等，不同的可执行文件都能通过JDBC访问数据库，又兼备存储的优势。简单说它就是Java与数据库的连接的桥梁或者插件，用Java代码就能操作数据库的增删改查、存储过程、事务等。

我们可以发现，JDK自带了一个`java.sql`包，而这里面就定义了大量的接口，不同类型的数据库，都可以通过实现此接口，编写适用于自己数据库的实现类。而不同的数据库厂商实现的这套标准，我们称为`数据库驱动`。

## 使用前准备

将mysql驱动jar依赖导入到项目中，下载地址：[http://dev.mysql.com/downloads/connector/j/](http://dev.mysql.com/downloads/connector/j/)，这是MySQL的官方实现，也可以使用其他相应版本的数据库驱动。

## 使用JDBC连接数据库

总共分为四步进行：

+ 首先使用DriverManager获得数据库连接

```java
Connection connection = DriverManager.getConnection("URL","root","password");
```

+ 创建一个用于执行SQL的Statement对象

```java
 Statement statement = connection.createStatement();
```

注意：以上两个对象使用后均需要释放，可以使用try-with-resource自动释放资源。若出现错误，将抛出`SQLException`异常。

+ 使用`statement.executeQuery`执行SQL语句并且范围结果集

```java
ResultSet set = statement.executeQuery("select * from teacher");
```

+ 遍历结果集对结果进行操作

```java
System.out.println(set.getString(1));
```

测试代码：

```java
import java.sql.*;

public class JDBC {
    public static void main(String[] args) {
        try (Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/study","root","998244353");
        Statement statement = connection.createStatement()) {
            ResultSet set = statement.executeQuery("select * from teacher");
            while (set.next()) {
                System.out.println(set.getString(2));
            }
        }catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
```

## 了解DriverManager

我们首先来了解一下DriverManager是什么东西，它其实就是管理我们的数据库驱动的：

```java
public static synchronized void registerDriver(java.sql.Driver driver,
        DriverAction da)
    throws SQLException {

    /* Register the driver if it has not already been added to our list */
    if(driver != null) {
        registeredDrivers.addIfAbsent(new DriverInfo(driver, da));    //在刚启动时，mysql实现的驱动会被加载，我们可以断点调试一下。
    } else {
        // This is for compatibility with the original DriverManager
        throw new NullPointerException();
    }

    println("registerDriver: " + driver);

}
```

我们可以通过调用getConnection()来进行数据库的链接：

```java
@CallerSensitive
public static Connection getConnection(String url,
    String user, String password) throws SQLException {
    java.util.Properties info = new java.util.Properties();

    if (user != null) {
        info.put("user", user);
    }
    if (password != null) {
        info.put("password", password);
    }

    return (getConnection(url, info, Reflection.getCallerClass()));   //内部有实现
}
```

我们可以手动为驱动管理器添加一个日志打印：

```java
static {
    DriverManager.setLogWriter(new PrintWriter(System.out));   //这里直接设定为控制台输出
}
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/03/jdbc-1/  

