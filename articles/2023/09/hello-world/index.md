# Hello World


This is the post for functional testings.

<!--more-->

# Hello World

## 2-nd title

Hello, world!

## code

```python
from pwn import *
context(arch='amd64',os='linux')
context.terminal=['tmux','splitw','-h']
```

```c++
#include <iostream>
#include <cstdio>
using namespace std;

int main() {
    cout << "Hello, world!";
    return 0;
}
```

`echo 'inline code';`

I need some long java code to test.

```java
import java.util.ArrayList;
import java.util.Scanner;

class TodoApp {
    private ArrayList<String> todoList;

    public TodoApp() {
        todoList = new ArrayList<>();
    }

    public void addTask(String task) {
        todoList.add(task);
        System.out.println("任务 '" + task + "' 已添加到待办事项列表。");
    }

    public void viewTasks() {
        if (todoList.isEmpty()) {
            System.out.println("待办事项列表为空。");
        } else {
            System.out.println("待办事项列表:");
            for (int i = 0; i < todoList.size(); i++) {
                System.out.println((i + 1) + ". " + todoList.get(i));
            }
        }
    }

    public void removeTask(int taskIndex) {
        if (taskIndex >= 1 && taskIndex <= todoList.size()) {
            String removedTask = todoList.remove(taskIndex - 1);
            System.out.println("任务 '" + removedTask + "' 已从待办事项列表中移除。");
        } else {
            System.out.println("无效的任务索引。");
        }
    }
}

public class Main {
    public static void main(String[] args) {
        TodoApp todoApp = new TodoApp();
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n待办事项应用");
            System.out.println("1. 添加任务");
            System.out.println("2. 查看任务");
            System.out.println("3. 移除任务");
            System.out.println("4. 退出");
            System.out.print("请选择操作: ");

            String choice = scanner.next();

            if ("1".equals(choice)) {
                System.out.print("请输入任务名称: ");
                String task = scanner.next();
                todoApp.addTask(task);
            } else if ("2".equals(choice)) {
                todoApp.viewTasks();
            } else if ("3".equals(choice)) {
                System.out.print("请输入要移除的任务索引: ");
                int taskIndex = scanner.nextInt();
                todoApp.removeTask(taskIndex);
            } else if ("4".equals(choice)) {
                break;
            } else {
                System.out.println("无效的选项，请重新选择。");
            }
        }

        scanner.close();
    }
}
```

## math

$sin(x^2)$



$\int u \frac{\mathrm{d}v}{\mathrm{d}x}\,\mathrm{d}x=uv-\int \frac{\mathrm{d}u}{\mathrm{d}x}v\,\mathrm{d}x $



$f(x) = \int_{-\infty}^\infty  \hat f(x)\xi\,e^{2 \pi i \xi x}  \,\mathrm{d}\xi$

------



$\ce{SO4^2- + Ba^2+ -> BaSO4 v}$

# Test page

> This is a quote.

{{< admonition tip >}}
当你运行 `hugo server` 时，当文件内容更改时，页面会随着更改自动刷新。
{{< /admonition >}}

Typora don't make it.

"在未来的**数字时代**，人工智能将继续深刻地改变我们的生活。机器学习算法将变得更加智能，*自动驾驶汽车*将成为常态，医疗保健将变得更加精确，而人们将与虚拟现实世界互动，不仅仅是在娱乐领域，还包括教育和工作。这个数字化的未来将带来无限的可能性，但也需要我们审慎思考和管理与之相关的伦理和<u>隐私问题</u>。"


---

> 作者: alextang  
> URL: https://alextang.top/articles/2023/09/hello-world/  

