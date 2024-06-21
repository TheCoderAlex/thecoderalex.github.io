# LeetCode-总行驶距离

> [2739. 总行驶距离](https://leetcode.cn/problems/total-distance-traveled/)-Easy

### 题目

卡车有两个油箱。给你两个整数，`mainTank` 表示主油箱中的燃料（以升为单位），`additionalTank` 表示副油箱中的燃料（以升为单位）。

该卡车每耗费 `1` 升燃料都可以行驶 `10` km。每当主油箱使用了 `5` 升燃料时，如果副油箱至少有 `1` 升燃料，则会将 `1` 升燃料从副油箱转移到主油箱。

返回卡车可以行驶的最大距离。

注意：从副油箱向主油箱注入燃料不是连续行为。这一事件会在每消耗 `5` 升燃料时突然且立即发生。

**示例 1：**

```
输入：mainTank = 5, additionalTank = 10
输出：60
解释：
在用掉 5 升燃料后，主油箱中燃料还剩下 (5 - 5 + 1) = 1 升，行驶距离为 50km 。
在用掉剩下的 1 升燃料后，没有新的燃料注入到主油箱中，主油箱变为空。
总行驶距离为 60km 。
```

**示例 2：**

```
输入：mainTank = 1, additionalTank = 2
输出：10
解释：
在用掉 1 升燃料后，主油箱变为空。
总行驶距离为 10km 。
```

### 思路

这题没啥好说的，就是每五升油，从副油箱换一升油，直到换完。剩下的油一升10公里。

不会数学推导，直接模拟。

```java
class Solution {
    public int distanceTraveled(int mainTank, int additionalTank) {
        int sum = 0;
        while (mainTank - 5 >= 0) {
            if (additionalTank >= 1) {
                mainTank -= 4;
                additionalTank -=1;
            } else {
                mainTank -= 5;
            }
            sum += 5 * 10;
        }
        if (mainTank > 0)
            sum += mainTank * 10;
        return sum;
    }
}
```



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/04/leetcode-4.25/  

