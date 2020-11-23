# shellcode
我的免杀shellcode

Blog: https://9bie.org

原理:  https://9bie.org/index.php/archives/531/

## 2020/11/23 更新

使用 [httpLIB](https://github.com/yhirose/cpp-httplib) 重构了请求方法，不会再造成socket管道残留的问题，并且支持https

# Server.py

payload分发服务器，可以动态修改payload
下次服务端请求时才会调用

# Client

本体，可以直接编译运行和分为dll运行，编译后dll入口点为dll

请把文件内target修改为Server.py的访问地址，记住不要带其他url

# Install

自带一个默认安装方式

使用gcc编译后，请把client编译成dll后改名为invoke.dll，确保三个文件

	- svchost.exe
	- install.bat
	- invoke.dll

三个文件在同一目录，使用管理员权限运行install.bat之后，就会安装一个服务

或者自行使用其他方式安装