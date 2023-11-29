# FireWall-with-Netfliter

基于Netfilter的Linux状态检测防火墙，支持NAT（ 华中科技大学2023学年网络安全课程设计项目，参考https://github.com/RicheyJang/RJFireWall ）

## Updates
⭐️2023.11.29: NAT实现其实是有问题的，直接把NAT规则表当NAT表用了，可能会出现不支持多条TCP连接的情况，大家可以直接用原项目的NAT（原项目虽然建反向连接不太合理，但是功能是OK的），也欢迎有余力的同学加个NAT表。感谢gls提出的问题。

⭐️2023.11.29: NAT无法处理ICMP报文，所以会出现开了NAT ping不通的情况，原项目也存在这个问题，因为ICMP报文没有端口信息，涉及到伪端口的设计等等。感谢gls的反馈。

⭐️2023.11.29: 修复了NAT内网判断的bug， 详见commit https://github.com/JJJYmmm/FireWall-with-Netfliter/commit/65bcab15fe8e69d9cbf95c6774abc9e9223cf721

## 一些改动
- 用python重写了前端，参数检查更方便（单纯套了一个壳子）
- 修复日志记录的报文长度bug（大小端转换问题）
- 优化NAT逻辑，使其和连接解耦，不需要再添加反向连接（最麻烦的一部分，感谢yjy陪伴）

## 更多说明
- 可以直接**把kernel_mod文件夹替换到RJFireWall中**，使用它的前端即可(绝对不是自己不想写Readme)
- 具体改动见文档PDF，希望不要完全借鉴(怕查重)
- 多给原项目 https://github.com/RicheyJang/RJFireWall 点点star，隔空谢谢学长！
- 祝大家考研顺利！

## Acknowlegement
坐上那飞机去拉萨（civi粉丝版）

## Contributions
- NAT TCP改动（yjy）
- 日志改动（gls）
