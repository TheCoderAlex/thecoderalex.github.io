# JavaEE Socket基础


## Socket技术

`Socket`技术也被称为套接字，是操作系统底层提供的一项通信技术，同时支持`TCP`和`UDP`。要实现Socket通信，我们必须创建一个数据发送者和一个数据接收者，也就是客户端和服务端，我们需要提前启动服务端，来等待客户端的连接，而客户端只需要随时启动去连接服务端即可！

使用Java启动Socket服务端对象：

```java
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String[] args) {
        try(ServerSocket server = new ServerSocket(8080)) {
            System.out.println("Waiting for client...");
            while (true) {
                Socket socket = server.accept();
                System.out.println("Client has connected! The ip is: " + socket.getInetAddress().getHostAddress());
            }
        }catch (IOException e) {
            System.out.println("Server error!");
            e.printStackTrace();
        }
    }
}
```

创建客户端（实际上就是连接服务端的套接字而已）

```java
import java.io.IOException;
import java.net.Socket;

public class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost",8080)) {
            System.out.println("Connection established!");
        } catch (IOException e) {
            System.out.println("Connection error!");
            e.printStackTrace();
        }
    }
}
```

实际上，建立Socket的过程就是`TCP`三次握手的过程：

![](https://image.itbaima.cn/markdown/2023/07/22/N4ytU8MqTxVL26X.png)

通过在`accept()`阶段加上循环，就可以实现接受多个客户端的连接。

## 使用Socket进行数据传输

Socket对象提供了对应的输入输出IO流进行网络数据传输。为了不用一个Byte的读取和发送数据，可以使用`OutputStreamWriter`和`InputStreamReader`来实现字符的输入和输出。同时可以使用`BufferedReader`缓冲字符流从缓冲区中读入数据。

服务端代码如下：

```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String[] args) {
        try(ServerSocket server = new ServerSocket(8080)) {
            System.out.println("Waiting for client...");
            Socket socket = server.accept();
            System.out.println("Client has connected! The ip is: " + socket.getInetAddress().getHostAddress());
            System.out.println("Waiting for the message...");
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String message = reader.readLine();
            System.out.println("Receive message from client: " + message);
            OutputStreamWriter writer = new OutputStreamWriter(socket.getOutputStream());
            writer.write("Receive message: " + message);
            writer.flush();
            socket.close();
        }catch (IOException e) {
            System.out.println("Server error!");
            e.printStackTrace();
        }
    }
}
```

客户端代码如下：

```java
import java.io.*;
import java.net.Socket;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost",8080);
             Scanner scanner = new Scanner(System.in)) {
            System.out.println("Connection established!");
            OutputStreamWriter writer = new OutputStreamWriter(socket.getOutputStream());
            String text = scanner.nextLine();
            writer.write(text + '\n');
            writer.flush();
            System.out.println("Text has been sent: " + text);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            System.out.println("Receive respond from server: " + reader.readLine());
        } catch (IOException e) {
            System.out.println("Connection error!");
            e.printStackTrace();
        }
    }
}
```

在服务器的设置上，可以手动关闭某个方向的流。

```java
socket.shutdownOutput();  //关闭输出方向的流
socket.shutdownInput();  //关闭输入方向的流
```

同时可以通过调用`setSoTimeout()`设置超时时间：

```java
socket.setSoTimeout(3000);
```

如果连接的双方发生意外而通知不到对方，导致一方还持有连接，这样就会占用资源，因此我们可以使用`setKeepAlive()`方法来防止此类情况发生：

```java
socket.setKeepAlive(true);
```

![img](https://image.itbaima.cn/markdown/2023/03/06/j7Ba4IYxQDsVyLq.jpg)



## 使用Socket传输文件

由于提供了IO网络流，结合文件IO流就可以实现文件的传输。使用`FileOutputStream`和`FileInputStream`进行文件的输出和输入。

这里和IO部分的内容差不多，不再进行叙述。

## 使用浏览器访问Socket服务器

HTTP协议是基于TCP协议的，如果使用HTTP协议访问Socket服务器，服务器就会收到一个HTTP请求：

```java
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String[] args) {
        try(ServerSocket server = new ServerSocket(8080)) {
            System.out.println("Waiting for client...");
            Socket socket = server.accept();
            System.out.println("Client has connected! The ip is: " + socket.getInetAddress().getHostAddress());
            InputStream stream = socket.getInputStream();
            while (true) {
                int i = stream.read();
                if (i == -1)    break;
                System.out.print((char) i);
            }
        }catch (IOException e) {
            System.out.println("Server error!");
            e.printStackTrace();
        }
    }
}
```

打印出的请求如下：

```
Waiting for client...
Client has connected! The ip is: 127.0.0.1
GET / HTTP/1.1
Host: 127.0.0.1:8080
Connection: keep-alive
sec-ch-ua: "Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9
```

这就是一个标准的HTTP协议请求。但是由于Socket没有返回，所以浏览器不能正常显示页面。

---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/03/javaee-socket/  

