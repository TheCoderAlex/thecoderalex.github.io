# LeetCode-快照数组


> [1146. 快照数组](https://leetcode.cn/problems/snapshot-array/)

### 题目

实现支持下列接口的「快照数组」- SnapshotArray：

- `SnapshotArray(int length)` - 初始化一个与指定长度相等的 类数组 的数据结构。**初始时，每个元素都等于** **0**。
- `void set(index, val)` - 会将指定索引 `index` 处的元素设置为 `val`。
- `int snap()` - 获取该数组的快照，并返回快照的编号 `snap_id`（快照号是调用 `snap()` 的总次数减去 `1`）。
- `int get(index, snap_id)` - 根据指定的 `snap_id` 选择快照，并返回该快照指定索引 `index` 的值。

**示例：**

```
输入：["SnapshotArray","set","snap","set","get"]
     [[3],[0,5],[],[0,6],[0,0]]
输出：[null,null,0,null,5]
解释：
SnapshotArray snapshotArr = new SnapshotArray(3); // 初始化一个长度为 3 的快照数组
snapshotArr.set(0,5);  // 令 array[0] = 5
snapshotArr.snap();  // 获取快照，返回 snap_id = 0
snapshotArr.set(0,6);
snapshotArr.get(0,0);  // 获取 snap_id = 0 的快照中 array[0] 的值，返回 5
```

**提示：**

- `1 <= length <= 50000`
- 题目最多进行`50000` 次`set`，`snap`，和 `get`的调用 。
- `0 <= index < length`
- `0 <= snap_id < `我们调用 `snap()` 的总次数
- `0 <= val <= 10^9`

### 思路

很抽象的表述。反正就是维护一个数组，在需要的时候储存一个当前数组状态的备份。然后同时支持取出相应时间的数组数据。

很容易想到使用HashMap维护一个快照id到数组的状态。但是实际测试中，由于每次都需要创建一个新的数组对象插入HashMap中，因此会导致`MLE` 。

这里的问题出在，每次都将数组所有的元素保存下来。但是每次查询并不需要维护整个数组，只需要输出相应数组元素即可。

因此可以使用一个`TreeMap` （key有序，可以在查找上变得快一点），维护一个`snap_id` 到元素值的映射，同时外层又有一个HashMap映射到该Map上。这样，相当于数组的每个元素都是一个TreeMap，保存着历史的备份。

那么，只需要在插入节点的情况下，在HashMap中插入一个TreeMap，接着将值保存在相应的`snap_id` 中。

```java
public void set(int index, int val) {
        mp.computeIfAbsent(index, key -> new TreeMap<>()).put(snap_id, val);
}
```

每次查询，首先判断mp中index元素是否存在，不存在就是0，存在的话就从TreeMap中寻找值是snap_id的key即可。

```java
public int get(int index, int snap_id) {
    Map.Entry<Integer, Integer> entry = mp.computeIfAbsent(index, key -> new TreeMap<>()).floorEntry(snap_id);
    return entry == null ? 0 : entry.getValue();
}
```

完整代码：

```java
class SnapshotArray {
    Map<Integer, TreeMap<Integer, Integer>> mp;
    int snap_id;
    public SnapshotArray(int length) {
        snap_id = 0;
        mp = new HashMap<>();
    }
    
    public void set(int index, int val) {
        mp.computeIfAbsent(index, key -> new TreeMap<>()).put(snap_id, val);
    }
    
    public int snap() {
        return snap_id++;
    }
    
    public int get(int index, int snap_id) {
        Map.Entry<Integer, Integer> entry = mp.computeIfAbsent(index, key -> new TreeMap<>()).floorEntry(snap_id);
        return entry == null ? 0 : entry.getValue();
    }
}

/**
 * Your SnapshotArray object will be instantiated and called as such:
 * SnapshotArray obj = new SnapshotArray(length);
 * obj.set(index,val);
 * int param_2 = obj.snap();
 * int param_3 = obj.get(index,snap_id);
 */
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/04/leetcode-4.26/  

