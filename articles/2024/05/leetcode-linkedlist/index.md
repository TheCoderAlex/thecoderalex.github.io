# leetcode整理：链表


## 移除链表

建议是直接加上虚拟头节点，也就是头元素指向链表的第一个元素。这样每次删除只需要找到待删除元素的前一个点`pre` ，然后删除节点`node` 。

```java
pre.next = pre.next.next;
```

## 实现一个链表

```java
class MyLinkedList {
    int size;
    Node head;

    public MyLinkedList() {
        size = 0;
        head = new Node(0);
    }
    
    public int get(int index) {
        if (index < 0 || index >= size)
            return -1;
        Node p = head;
        for (int i = 0;i <= index;++i){
            p = p.next;
        }
        // Node test = head;
        // while (test != null) {
        //     System.out.print(test.val + " ");
        //     test = test.next;
        // }
        // System.out.print("size: " + this.size + "\n");
        return p.val;
    }
    
    public void addAtHead(int val) {
        Node insert = new Node(val);
        insert.next = head.next;
        head.next = insert;
        size++;
    }
    
    public void addAtTail(int val) {
        Node insert = new Node(val);
        Node p = head.next;
        size++;
        if (p == null) {
            head.next = insert;
            return;
        }
        while (p != null && p.next != null)
            p = p.next;
        p.next = insert;
        insert.next = null;
    }
    
    public void addAtIndex(int index, int val) {
        if (index > size)
            return;
        if (index < 0)
            index = 0;
        Node p = head;
        Node insert = new Node(val);
        for (int i = 0;i < index;++i)
            p = p.next;
        insert.next = p.next;
        p.next = insert;
        size++;
    }
    
    public void deleteAtIndex(int index) {
        if (index < 0 || index >= size) 
            return;
        if (index == 0) {
            head = head.next;
            size--;
            return;
        }
        Node p = head;
        for (int i = 0;i < index;++i)
            p = p.next;
        p.next = p.next.next;
        size--;
    }
}

class Node {
    int val;
    Node next;
    Node (){}
    Node (int val){
        this.val = val;
    }
}
/**
 * Your MyLinkedList object will be instantiated and called as such:
 * MyLinkedList obj = new MyLinkedList();
 * int param_1 = obj.get(index);
 * obj.addAtHead(val);
 * obj.addAtTail(val);
 * obj.addAtIndex(index,val);
 * obj.deleteAtIndex(index);
 */
```

## 反转链表

保存每个节点的前置节点，然后每次对每个节点进行反转，让其`next` 等于`pre`。

```java
while (cur) {
    ListNode tmp = cur.next;
    cur.next = pre;
    pre = cur;
    cur = tmp;
}
```

## 交换相邻元素

模拟即可，使用虚拟头节点，交换下一个和下下一个节点。

```java
while (cur.next != null && cur.next.next != null) {
        temp = cur.next.next.next;
        firstnode = cur.next;
        secondnode = cur.next.next;
        cur.next = secondnode;       // 步骤一
        secondnode.next = firstnode; // 步骤二
        firstnode.next = temp;      // 步骤三
        cur = firstnode; // cur移动，准备下一轮交换
    }
```

## 删除倒数N节点

双指针的经典应用，如果要删除倒数第n个节点，让fast移动n步，然后让fast和slow同时移动，直到fast指向链表末尾。删掉slow所指向的节点就可以了。

> 让fast和slow相差n个节点，然后fast移动到链表末尾，则slow就是要删除的节点。

## 链表相交

题意是链表相交之后公用了一条链表。假设A链表的长度为`lena`, B链表的长度为`lenb` ，那么相交的公共节点最早也要出现在`lena - lenb` 的位置（假设lena > lenb）。换句话说就是两个链表在相交之后不可能再分开。

那么就从同时遍历短链表的长度，找找有没有相同的节点即可，

## 环形链表

双指针的经典应用，快指针每次走两格，慢指针每次走一个，快指针如果能再次和慢指针相遇，则说明有环。

关于环的入口，在快慢指针相遇的地方再次出发一个指针，如果再次相遇，相遇点就是环的入口处。

> 链表的大部分题目还是模拟，但是偶尔会有快慢指针的题目，需要额外注意一下。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/05/leetcode-linkedlist/  

