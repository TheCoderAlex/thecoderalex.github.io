# LeetCode-感染二叉树需要的总时间


>  [2385. 感染二叉树需要的总时间](https://leetcode.cn/problems/amount-of-time-for-binary-tree-to-be-infected/)-Medium

### 题目

给你一棵二叉树的根节点 `root` ，二叉树中节点的值 **互不相同** 。另给你一个整数 `start` 。在第 `0` 分钟，**感染** 将会从值为 `start` 的节点开始爆发。

每分钟，如果节点满足以下全部条件，就会被感染：

- 节点此前还没有感染。
- 节点与一个已感染节点相邻。

返回感染整棵树需要的分钟数。

### 思路

就是算从这个节点出发，到达最远节点的距离。那么有个很直观的想法就是做BFS。但是，树上的节点并没有办法存父亲节点的位置。所以首先要将树结构转为图。个人觉得何种遍历方式都可以，只是需要额外保存一个父亲节点的值而已。

```java
int[][] mp = new int[100010][];
    int m = 0;
    public void dfs(TreeNode node, int father) {
        if (node == null)   return;
        if (node.val > m)   m = node.val;
        int[] e = new int[3];
        if (node.left != null)  e[0] = node.left.val;
        if (node.right != null) e[1] = node.right.val;
        e[2] = father;
        mp[node.val] = e;
        dfs(node.left, node.val);
        dfs(node.right, node.val);
    }
```

这里为了省事，直接每个节点都保存三个值：左孩子，右孩子和父亲。有一个节点是没有父亲的，就是根节点，此时的父亲值为0（即代表不存在父亲）。等图建好后就可以使用BFS进行寻路了。每次更新最大值，等到BFS结束即可取到最终的结果。

```java
public int amountOfTime(TreeNode root, int start) {
        dfs(root, 0);
        boolean[] vis = new boolean[m + 1];
        Queue<int[]> q = new LinkedList<>();
        q.add(new int[]{start, 0}); 
        vis[start] = true;
        int res = 0;
        while (!q.isEmpty()) {
            int[] top = q.remove();
            int node = top[0];
            int minute = top[1];
            res = Math.max(res, minute);
            for (int i = 0; i < 3; ++i) {
                int t = mp[node][i];
                if (t == 0 || vis[t]) continue;
                q.add(new int[]{t, minute + 1});
                vis[t] = true;
            }
        }
        return res;
    }
```

题目不难，难在`1e5` 的数据量上。本来以为会超时，其实很快。


---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/04/leetcode-4-24/  

