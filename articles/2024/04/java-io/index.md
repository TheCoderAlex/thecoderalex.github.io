# Java IO优化


## Java IO优化

使用`Scanner`进行输入输出会非常方便，但是当读入或者输出的数据量超过$10^5$ 的数量级时，很容易TLE（Java在算法题中的时限一般为2s）。于是我们可以使用`BufferedReader`和`PrintWriter`（或者`BufferedWriter`）进行输入输出。

头文件（如果非要一个个全写出来的话）：

+ `java.io.BuffereReader`
+ `java.io.BufferedWriter`
+ `java.io.InputStreamReader`
+ `java.io.OutputStreamWriter`
+ `java.io.PrintWriter`
+ `java.io.IOException`

我的建议是`java.io.*`会好一点。

另外，不要忘记抛出异常！

输入输出样例：

```java
import java.io.*;
public class Main {
    public static void main(String[] args) throws IOException{
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(System.out));
        BufferedWriter wout = new BufferedWriter(new OutputStreamWriter(System.out)); 
       
        //BufferedReader只能返回一行的String
        String t = in.readLine();
        //接下来根据需要对t进行处理即可
        int n = Integer.parseInt(t);
        double l = Double.parseDouble(t);
        long s = Long.parseLong(t);
        //特别的，如果出现一行多个使用空格分割的情况，使用String类的split()方法进行分割
        String[] strArr = in.readLine().split(" ");
        //对于多组数据的读入，readLine()读到EOF会返回null
        while(t = in.readLine() != null) {
            //...
        }
       	
        //PrintWriter的输出方法和System.out一致
        out.print(t);
        out.printf("%.2f\n", l);
        //BufferedWriter则使用write函数
        wout.write("Hello");
        //这两种方法一定记得使用flush()刷新缓冲区到屏幕，整个程序只需要刷新一次即可
        out.flush()
    }
}
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/04/java-io/  

