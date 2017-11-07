# 目录结构

src/backdoor.c 后门程序实现
src/hidenetstat.c netstat隐藏实现

# Tips

后门程序针对于获取root 权限的shell，所以需要修改可执行文件的所有者为root，并设置setuid
连接后门程序可直接使用nc命令，端口号为1234