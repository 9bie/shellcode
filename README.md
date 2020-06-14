# shellcode
我的免杀shellcode
Blog: https://9bie.org
原理:  https://9bie.org/index.php/archives/531/
# server.py

payload分发服务器，可以动态修改payload
下次重启时才会引用
# Invode
Dll版本，导入不带入口点，入口点请调用Invoke执行

可以自行注入或者使用`Rundll32`方式调用

# purebin
作用于PC，目前过360启动保护，完全无杀软弹窗。

直接运行即可。


# Svchost
一个单纯的服务器文件，配合DLL使用，推荐使用GCC编译，免杀效果更佳

使用时请用当前目录的下的`install.bat`，以及上面Invode编译的`Invoke.dll`三个文件于同一目录

或者自行用sc创建服务。