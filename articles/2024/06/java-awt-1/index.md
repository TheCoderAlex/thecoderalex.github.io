# Java AWT 创建窗口


## 使用AWT创建一个窗口
AWT中每个窗口单位是以 `Frame` 为单位的，我们可以使用 `Frame` 来创建一个窗口。

```java
package com.alextang;

import java.awt.*;

public class Main {
    public static void main(String[] args) {
        Frame frame = new Frame();
    }
}
```

但是默认的 `Frame` 是不可见的，此时可以通过 `setVisible` 方法来使其可见。

```java
package com.alextang;

import java.awt.*;

public class Main {
    public static void main(String[] args) {
        Frame frame = new Frame();
        
        frame.setVisible(true);
    }
}
```

现在，窗口应该可以显示在屏幕的左上角。并且大小非常小。下面将讨论 `Frame` 其他的一些方法，来让这个窗口变的更好看一点。

## Frame常用方法

先上代码：

```java
package com.alextang;

import java.awt.*;

public class Main {
    public static void main(String[] args) {
        Frame frame = new Frame();
        frame.setSize(500, 300);

        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        int x = (int) (screenSize.getWidth() / 2 - (double) frame.getWidth() / 2);
        int y = (int) (screenSize.getHeight() / 2 - (double) frame.getHeight() / 2);
        frame.setLocation(x, y);

        frame.setAlwaysOnTop(true);
        // frame.setResizable(false)
        // frame.setLocationRelativeTo(null);

        frame.setCursor(new Cursor(Cursor.HAND_CURSOR));
        frame.setVisible(true);
    }
}
```
主要涉及到这几个方法：

+ `setSize` 设置窗口的大小，单位是像素。
+ `setLocation` 设置窗口所在的位置。这个位置实际上是指左上角的点在屏幕上点的坐标。
+ `setAlwaysOnTop` 设置窗口是否永远在顶层，不会因为失焦而让其被其他窗口遮挡。
+ `setResizable` 设置窗口大小是否可以被用户调整。
+ `setLocationRelativeTo` 设置该窗口位于另外一个窗口的中心位置。特别的，如果参数值为 `null` ，那么该窗口将位于整个窗口的中心位置。
+ `setCursor` 设置指针位于窗口内部时指针的样式。需要一个 `Cursor` 对象作为参数。

## 关于窗口位置居中

并没有一个特别的函数使当前窗口相对于整个屏幕居中，但是，参照上述，可以使用 `setLocationRelativeTo(null)` 来实现窗口位置相对于屏幕居中。当然，还有另外一种办法，就是在设置好窗口的大小后，根据屏幕的大小和窗口的大小 `setLocation` 到相应的位置。

> 注意屏幕中心的位置实际上是窗口左上角向左上方移动 $\frac{1}{2}$ 个对角线的距离。

于是可以写出如下代码：

```java
Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
int x = (int) (screenSize.getWidth() / 2 - (double) frame.getWidth() / 2);
int y = (int) (screenSize.getHeight() / 2 - (double) frame.getHeight() / 2);
frame.setLocation(x, y);
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/06/java-awt-1/  

