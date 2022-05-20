from typing import Union, Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as sig_pk
from Crypto.Hash import MD5


def gener_pub_key():
    """

    :return: 返回字节流类型(bytes)的公钥，私钥存储在同级目录下的private.pem内
    """
    key = RSA.generate(1024)
    public_key = key.public_key().export_key()
    private_key = key.export_key()
    with open('private.pem', 'wb') as fp:
        fp.write(private_key)
    return public_key


def encrypt(public_key: bytes, message: bytes, is_base64=False) -> Union[str, bytes]:
    """

    :param public_key: 公钥，bytes类型
    :param message: 被加密的信息，可以是字符串，也可以是字节流
    :param is_base64: 是否需要对被加密的内容进行base64编码，默认是False
    :return: 字符串或字节流，根据传入参数is_base64决定
    """
    key = RSA.import_key(public_key)
    encrypts = PKCS1_v1_5.new(key)
    if is_base64:
        import base64
        return base64.b64encode(encrypts.encrypt(message)).decode()
    return encrypts.encrypt(message)


def decrypt(private_key: bytes, messsage: Union[bytes, str]):
    """

    :param private_key: 私钥，bytes类型
    :param messsage: 密文，可以是bytes或str，但如果是str，需要传入经过Base64编码后的字符串
    :return: 如果message是str，先解码（base64解码），再解密（RSA私钥解密），返回解密后的结果
    """
    if isinstance(messsage, str):
        import base64
        message = base64.b64decode(messsage.decode())
    key = RSA.import_key(private_key)
    decrypts = PKCS1_v1_5.new(key)
    return decrypts.decrypt(messsage, None)


def sig(private: bytes, hash_message: MD5.MD5Hash) -> bytes:
    """
    签名，通过私钥（private）签名
    :param private: type bytes，私钥
    :param hash_message: type: Crypto.Hash.MD5.new()，参考Get_Md5.py里的注释
    :return: bytes
    """
    sigs = RSA.import_key(private)
    sig_pkcs = sig_pk.new(sigs)
    return sig_pkcs.sign(hash_message)


def verify(public: bytes, signature: bytes, md5: MD5.MD5Hash) -> Optional[bool]:
    """
    Optional[bool]：要么返回bool类型，要么什么都不返回，即返回None（无）
    验签，公钥验签
    :param public: 公钥，字节流类型
    :param signature: 方法sig()返回的字节流，即经过签名得到的字节流
    :param md5: 参考Get_Md5.py，需要的参数为该文件里方法的返回值或其相同类型变量
    :return: 如果验证成功，返回true，否则抛出异常ValueError（就是报错，就是这么设计的，问就是出厂设置）,返回None
    """
    veri = RSA.import_key(public)
    veri_pkcs = sig_pk.new(veri)
    return veri_pkcs.verify(md5, signature)
