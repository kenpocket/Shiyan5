from typing import Union

from Crypto.Hash import MD5


def get_md5(message: Union[str, bytes]) -> MD5.MD5Hash:
    """

    :param message: 传入的参数可以是str字符串，也可以是bytes字节流
    :return: 返回的不是字符串，也不是字节流，是一个对象，经过update后的一个MD5.MD5Hash对象
    """
    md5 = MD5.new()
    md5.update(message if isinstance(message, bytes) else message.encode())
    '''
    isinstance(message, bytes)，意思是，判断message是不是bytes类型，如果是，返回true，否则返回false
    message if isinstance(message, bytes) else message.encode()等效于
    if isinstance(message, bytes):
        message = message
    else:
        message = message.encode()
    md5.hexdigest()的结果是我们常见的md5值，但本方法强调，返回的不是我们说的md5值，是一个实例化后的对象
    
    >>>from Crypto.Hash import MD5
    >>>md5 = MD5.new()
    >>>md5
    <Crypto.Hash.MD5.MD5Hash object at 0x0000017A2572EE20>
    >>>type(md5)
    <class 'Crypto.Hash.MD5.MD5Hash'>
    
    '''

    return md5
