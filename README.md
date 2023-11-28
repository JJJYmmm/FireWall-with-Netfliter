# FireWall-with-Netfliter

基于Netfilter的Linux状态检测防火墙，支持NAT（ 华中科技大学2023学年网络安全课程设计项目，参考https://github.com/RicheyJang/RJFireWall ）

一些改动:
- 用python重写了前端，参数检查更方便（单纯套了一个壳子）
- 修复日志记录的报文长度bug（大小端转换问题）
- 优化NAT逻辑，使其和连接解耦，不需要再添加反向连接（最麻烦的一部分，感谢yjy陪伴）


更多说明:
- 可以直接**把kernel_mod文件夹替换到RJFireWall中**，使用它的前端即可(绝对不是自己不想写Readme)
- 具体改动见文档PDF，希望不要完全借鉴(怕查重)
- 多给原项目 https://github.com/RicheyJang/RJFireWall 点点star，隔空谢谢学长！
- 祝大家考研顺利！

# Acknowlegement
坐上那飞机去拉萨（civi粉丝版）

# Contributions
- NAT TCP改动（yjy）
- 日志改动（gls）
