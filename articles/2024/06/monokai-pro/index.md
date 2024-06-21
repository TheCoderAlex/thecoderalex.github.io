# Monokai Pro主题破解


使用一个Linux终端，输入：

```bash
email=yourMail@mail.com
echo -n fd330f6f-3f41-421d-9fe5-de742d0c54c0$email | md5sum | cut -c1-25 | sed 's/.\{5\}/&-/g;s/-$//g'
```

其中，将 `yourMail@mai.com` 替换成任意的邮箱名称（不一定要可用）。第二行将输出相应邮件对应的序列号。

打开vscode，按下 `Ctrl+Shift+p` ，输入 `Monokai Pro: enter license`，回车后依次输入相应的邮件和序列号，即可注册成功。

---

> 作者: alextang  
> URL: https://alextang.top/articles/2024/06/monokai-pro/  

