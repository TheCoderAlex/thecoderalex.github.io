# leetcode整理：数组

## 二分查找

> 实现lower_bound和upper_bound

关键是掌握**循环不变量**

![](https://cdn.jsdelivr.net/gh/thecoderalex/imgs@upload/2023/image-20240507152819393.png)

以`lower_bound`为例。我们假设L所指的位置是最终的答案，且当R在L左边一格的时候退出循环（为什么是一格，因为每次只移动一格）。那么L左边的元素将全部满足$arr_i < t$ ，R右边的元素将全部满足$arr_i ≥ t$ 。此时的答案就是L所指元素。

为了满足上述假设，在每次循环中考察mid元素，若$arr_{mid} < t$，那么mid元素将属于L左边的区域。又因为数组递增，因此L应该移动到mid的右边。同理，$arr_{mid}≥t$的时候，mid元素应该属于R右边的区域。

lower_bound的实现如下：

```java
public static int lowerBound(int[] arr, int target, int left, int right) {
    if (left < 0 || right > arr.length)    return -1;
    right -= 1;
    while (left <= right) {
        int mid = (left + right) >> 1;
        if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return left >= arr.length ? -1 : left;
}
```

同理upper_bound：

```java
public static int upperBound(int[] arr, int target, int left, int right) {
    if (left < 0 || right > arr.length)    return -1;
    right -= 1;
    while (left <= right) {
        int mid = left + ((right - left) >> 1);
        //int mid = (left + right) >> 1;
        if (arr[mid] <= target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return left >= arr.length ? -1 : left;
}
```

## 移除元素

快慢指针，快指针遍历整个待操作数组，慢指针指在操作后数组的最后一位（也就是数组长度）。如果当前元素不要删除，那么就把该元素移动到慢指针的位置上，同时慢指针向后移动。

## 有序数组的平方

特殊的双指针，因为平方数必然在两端出现，自然从两边开始选取。

## 滑动窗口

滑动窗口适用于具有单调性的题目。换句话说，对一个数组的右端点右移会在某一刻满足（或不满足）条件，然后将其左端点右移，也会存在一个时刻不满足（或者满足）条件，在满足（或者不满足）条件的时刻求一个极值。

以[3. 无重复字符的最长子串](https://leetcode.cn/problems/longest-substring-without-repeating-characters/)为例，首先将右端点持续右移，直到区间中存在重复的字符，接着将左端点右移，删除字符，直到区间中不再存在重复的字符位置，计算此时子串的长度并保存目前的最大长度。

时间复杂度：由于数组的循环次数取决于左端点和右端点的移动次数，而数组中的每一个元素最多进入窗口一次，也最多出窗口一次，因此总体的时间复杂度是$O(n)$。代码如下：

```java
class Solution {
    public int lengthOfLongestSubstring(String s) {
        int ans = 0;
        int left = 0;
        Map<Character, Integer> cnt = new HashMap<>();
        char[] str = s.toCharArray();
        for (int right = 0; right < str.length; ++ right) {
            cnt.put(str[right], cnt.getOrDefault(str[right], 0) + 1);
            while (cnt.getOrDefault(str[right], 0) > 1) {
                cnt.put(str[left], cnt.get(str[left]) - 1);
                left++;
            }
            ans = Math.max(ans, right - left + 1);
        }
        return ans;
    }
}
```

## 模拟

[59. 螺旋矩阵 II](https://leetcode.cn/problems/spiral-matrix-ii/)

+ 分清边长的奇偶，是否存在中间的数字
+ 每条边只走`n - 1` 步，这样可以平均分给4条边长
+ 进入下一圈时，起点相当于沿着主对角线移动，移动的步数实际上减少两次。



---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/05/leetcode-arr/  

