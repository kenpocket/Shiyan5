
import base64
from Crypto.Cipher import DES
import random


def gener_DES_key():
    """
        通过调用random库，random.getrandbits(8)意思是获取一个8位长的字节（注意不是字节流，具体区别感兴趣的话自己百度）
        （该字节在python里以数字形式表示，大小<2的8次方），hex()将数字转化为16进制,例：hex(164)->'0xa4'
        replace('0x', ''),将生成的字符串前缀'0x'移除
    以上述方法循环16次，生成的hexs为16进制字符串
    bytes.fromhex()接受的参数必须是2的整数倍，因此要进行对2取余判断，如果不能整除，尾后补零
    keys = (bytes.fromhex(hexs) if (len(hexs) % 2) == 0 else bytes.fromhex(hexs + '0'))[0:8]等价于：
    if (len(hexs) % 2) == 0：
        keys = bytes.fromhex(hexs)[0:8]
    else:
        keys = bytes.fromhex(hexs + '0')[0:8]
    :return: 字节流,且长度为8
    """
    hexs = ''
    for i in range(16):
        hexs = hexs + hex(random.getrandbits(8)).replace('0x', '')
    keys = (bytes.fromhex(hexs) if (len(hexs) % 2) == 0 else bytes.fromhex(hexs + '0'))[0:8]
    return keys


def encrypt(message, key):
    """
    isinstance(key, bytes): 判断传入参数是否为bytes类型
    key if isinstance(key, bytes) else key.encode()等价于：
    if isinstance(key, bytes):
        key = key
    else:
        key = key.encode()
    :param message:
    :param key:
    :return:
    """
    a = b''
    if not len(key) % 8:
        key = key if isinstance(key, bytes) else key.encode()
    else:
        raise ValueError("Incorrect DES key length (%d bytes)" % len(key))
    des = DES.new(key, DES.MODE_ECB)
    b64_text = base64.b64encode(message)
    if len(b64_text) % 8 == 0:
        text_array = [b64_text[i:i + 8] for i in range(0, len(b64_text), 8)]
        """
        text_array = []
        for i in range(0, len(b64_text), 8):
            text_array.append(b64_text[i:i + 8])
        """
    else:
        text_array = b64_text + b'=' * (8 - len(b64_text) % 8)
        text_array = [text_array[i:i + 8] for i in range(0, len(b64_text), 8)]
        """
        text_array = []
        text_array2 = b64_text + b'=' * (8 - len(b64_text) % 8)
        for i in range(0, len(b64_text), 8):
            text_array.append(text_array2[i:i + 8])
        """
    for i in text_array:
        a += des.encrypt(i)
    return a


def decrypt(secret, keys):
    """
    流程：
    密文->经base64编码后的明文->明文

    :param secret: 密文，bytes类型
    :param keys: 密钥，bytes类型
    :return: 明文， bytes类型
    """
    des = DES.new(keys, DES.MODE_ECB)
    b64 = des.decrypt(secret)
    return base64.b64decode(b64)
