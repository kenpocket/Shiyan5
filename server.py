import random
import base64
from Crypto.Hash import MD5
from Crypto.Cipher import DES
from typing import Union
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as sig_pk
import socket

data = b''


def DES_decrypt(secret, keys):
    des = DES.new(keys, DES.MODE_ECB)
    b64 = des.decrypt(secret)
    return base64.b64decode(b64)


def gener_DES_key():
    hexs = ''
    for i in range(16):
        hexs = hexs + hex(random.getrandbits(8)).replace('0x', '')
    keys = (bytes.fromhex(hexs) if (len(hexs) % 2) == 0 else bytes.fromhex(hexs + '0'))[0:8]
    return keys


def get_md5(message: Union[str, bytes]):
    md5 = MD5.new()
    md5.update(message if isinstance(message, bytes) else message.encode())
    return md5


def DES_encrypt(message, key):
    a = b''
    if not len(key) % 8:
        key = key if isinstance(key, bytes) else key.encode()
    else:
        raise ValueError("Incorrect DES key length (%d bytes)" % len(key))
    des = DES.new(key, DES.MODE_ECB)
    b64_text = base64.b64encode(message)
    print(b64_text)
    if len(b64_text) % 8 == 0:
        text_array = [b64_text[i:i + 8] for i in range(0, len(b64_text), 8)]
    else:
        text_array = b64_text + b'=' * (8 - len(b64_text) % 8)
        text_array = [text_array[i:i + 8] for i in range(0, len(b64_text), 8)]
    for i in text_array:
        a += des.encrypt(i)
    return a


def gener_pub_key():
    key = RSA.generate(1024)
    public_key = key.public_key().export_key()
    private_key = key.export_key()
    with open('private.pem', 'wb') as fp:
        fp.write(private_key)
    return public_key


def RSA_encrypt(public_key: bytes, message: bytes, is_base64=False) -> str:
    key = RSA.import_key(public_key)
    encrypt = PKCS1_v1_5.new(key)
    if is_base64:
        import base64
        return base64.b64encode(encrypt.encrypt(message)).decode()
    return encrypt.encrypt(message)


def RSA_decrypt(private_key: bytes, messsage: Union[bytes, str]):
    if isinstance(messsage, str):
        import base64
        message = base64.b64decode(messsage.decode())
    key = RSA.import_key(private_key)
    decrypt = PKCS1_v1_5.new(key)
    return decrypt.decrypt(messsage, None)


def sig(private, message):
    """
    本方法用来签名，即公钥签名，私钥验签
    :param private: 公钥
    :param message: 待签名的信息，Crypto.Hash.MD5.new().update()后，参考GET_Md5.py里犯法返回的内容
    :return: 签名结果，类型为bytes，即字节流
    """
    sigs = RSA.import_key(private)
    sig_pkcs = sig_pk.new(sigs)
    return sig_pkcs.sign(message)


def verify(public, signature, md5):
    veri = RSA.import_key(public)
    veri_pkcs = sig_pk.new(veri)
    return veri_pkcs.verify(md5, signature)


if __name__ == '__main__':
    print('I am B, server.')
    public_key = gener_pub_key()
    print('local public key:', public_key)
    private_key = open('private.pem', 'rb').read()
    print('local private key:', private_key)
    con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    '''
    此处记得填写自己的主机（虚拟机或服务器）的内网ip地址（即ip addr/ipconfig/ifconfig显示的ip地址），端口任选（建议>1024且关闭防火墙等）
    '''
    con.bind(('192.168.74.129', 12500))



    con.listen(5)
    acc, _ = con.accept()
    # 一发， 发公钥
    acc.send(public_key)  # 发送公钥
    # 一收，收公钥
    other_pub = acc.recv(65535)  # other public key
    #  二收， 收DES密钥
    DES_key = acc.recv(65535)
    # 解密
    DES_key = RSA_decrypt(private_key, DES_key)
    # 三收 收DES加密后的文件内容
    file_sec = acc.recv(65535)
    # 解密
    file_text = DES_decrypt(file_sec, DES_key)
    print('file text:', file_text)
    #  四收，收文件MD5值
    file_md5 = acc.recv(65535)
    file_md5 = RSA_decrypt(private_key, file_md5)
    print("file_md5:", file_md5)
    #  五收，收文件签名
    sig_file = acc.recv(65535)
    md5s = get_md5(file_text)
    print(verify(other_pub, sig_file, md5=md5s))
    acc.close()
