# Junit


## 使用JUnit进行单元测试

首先一问：我们为什么需要单元测试？

随着我们的项目逐渐变大，比如我们之前编写的图书管理系统，我们都是边在写边在测试，而我们当时使用的测试方法，就是直接在主方法中运行测试，但是，在很多情况下，我们的项目可能会很庞大，不可能每次都去完整地启动一个项目来测试某一个功能，这样显然会降低我们的开发效率，因此，我们需要使用单元测试来帮助我们针对于某个功能或是某个模块单独运行代码进行测试，而不是启动整个项目。

同时，在我们项目的维护过程中，难免会涉及到一些原有代码的修改，很有可能出现改了代码导致之前的功能出现问题（牵一发而动全身），而我们又不一定能立即察觉到，因此，我们可以提前保存一些测试用例，每次完成代码后都可以跑一遍测试用例，来确保之前的功能没有因为后续的修改而出现问题。

我们还可以利用单元测试来评估某个模块或是功能的耗时和性能，快速排查导致程序运行缓慢的问题，这些都可以通过单元测试来完成，可见单元测试对于开发的重要性。

### 尝试JUnit

首先需要导入JUnit依赖，我们在这里使用Junit4进行介绍，最新的Junit5放到Maven板块一起讲解，Jar包已经放在视频下方简介中，直接去下载即可。同时IDEA需要安装JUnit插件（默认是已经捆绑安装的，因此无需多余配置）

现在我们创建一个新的类，来编写我们的单元测试用例：

```java
public class TestMain {
    @Test
    public void method(){
        System.out.println("我是测试用例1");
    }

    @Test
    public void method2(){
        System.out.println("我是测试用例2");
    }
}
```

我们可以点击类前面的测试按钮，或是单个方法前的测试按钮，如果点击类前面的测试按钮，会执行所有的测试用例。

运行测试后，我们发现控制台得到了一个测试结果，显示为绿色表示测试通过。

只需要通过打上`@Test`注解，即可将一个方法标记为测试案例，我们可以直接运行此测试案例，但是我们编写的测试方法有以下要求：

* 方法必须是public的
* 不能是静态方法
* 返回值必须是void
* 必须是没有任何参数的方法

对于一个测试案例来说，我们肯定希望测试的结果是我们所期望的一个值，因此，如果测试的结果并不是我们所期望的结果，那么这个测试就应该没有成功通过！

我们可以通过断言工具类来进行判定：

```java
public class TestMain {
    @Test
    public void method(){
        System.out.println("我是测试案例！");
        Assert.assertEquals(1, 2);    //参数1是期盼值，参数2是实际测试结果值
    }
}
```

通过运行代码后，我们发现测试过程中抛出了一个错误，并且IDEA给我们显示了期盼结果和测试结果，那么现在我们来测试一个案例，比如我们想查看冒泡排序的编写是否正确：

```java
@Test
public void method(){
    int[] arr = {0, 4, 5, 2, 6, 9, 3, 1, 7, 8};

    //错误的冒泡排序
    for (int i = 0; i < arr.length - 1; i++) {
        for (int j = 0; j < arr.length - 1 - i; j++) {
            if(arr[j] > arr[j + 1]){
                int tmp = arr[j];
                arr[j] = arr[j+1];
                // arr[j+1] = tmp;
            }
        }
    }

    Assert.assertArrayEquals(new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, arr);
}
```

通过测试，我们发现得到的结果并不是我们想要的结果，因此现在我们需要去修改为正确的冒泡排序，修改后，测试就能正确通过了。我们还可以再通过一个案例来更加深入地了解测试，现在我们想测试从数据库中取数据是否为我们预期的数据：

```java
@Test
public void method(){
    try (SqlSession sqlSession = MybatisUtil.getSession(true)){
        TestMapper mapper = sqlSession.getMapper(TestMapper.class);
        Student student = mapper.getStudentBySidAndSex(1, "男");

        Assert.assertEquals(new Student().setName("小明").setSex("男").setSid(1), student);
    }
}
```

那么如果我们在进行所有的测试之前需要做一些前置操作该怎么办呢，一种办法是在所有的测试用例前面都加上前置操作，但是这样显然是很冗余的，因为一旦发生修改就需要挨个进行修改，因此我们需要更加智能的方法，我们可以通过`@Before`注解来添加测试用例开始之前的前置操作：

```java
public class TestMain {

    private SqlSessionFactory sqlSessionFactory;
    @Before
    public void before(){
        System.out.println("测试前置正在初始化...");
        try {
            sqlSessionFactory = new SqlSessionFactoryBuilder()
                    .build(new FileInputStream("mybatis-config.xml"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        System.out.println("测试初始化完成，正在开始测试案例...");
    }

    @Test
    public void method1(){
        try (SqlSession sqlSession = sqlSessionFactory.openSession(true)){
            TestMapper mapper = sqlSession.getMapper(TestMapper.class);
            Student student = mapper.getStudentBySidAndSex(1, "男");

            Assert.assertEquals(new Student().setName("小明").setSex("男").setSid(1), student);
            System.out.println("测试用例1通过！");
        }
    }

    @Test
    public void method2(){
        try (SqlSession sqlSession = sqlSessionFactory.openSession(true)){
            TestMapper mapper = sqlSession.getMapper(TestMapper.class);
            Student student = mapper.getStudentBySidAndSex(2, "女");

            Assert.assertEquals(new Student().setName("小红").setSex("女").setSid(2), student);
            System.out.println("测试用例2通过！");
        }
    }
}
```

同理，在所有的测试完成之后，我们还想添加一个收尾的动作，那么只需要使用`@After`注解即可添加结束动作：

```java
@After
public void after(){
    System.out.println("测试结束，收尾工作正在进行...");
}
```


---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/03/junit/  

