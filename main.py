#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project ：Shiyan5
@File    ：main.py
@IDE     ：PyCharm
@Author  ：ggs
@Date    ：2022/5/9 0:15
"""
import socket
import DES_D_E,  RSA_D_E, Get_Md5
from time import sleep

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
message = open('main_2022-04-24.log', 'rb').read()
filename = 'main_2022-04-24.log'
md5 = Get_Md5.get_md5(message)
message_md5 = md5.digest().hex()
'''
一、建立socket连接
二、交换RSA密钥
三、发送DES密钥
四、信息传输阶段

'''
sock.connect(('192.168.74.129', 12500))
print('I am A,client.')
# 一 接
other_pub = sock.recv(65535)  # 接受对方公钥
# print('other pub:', other_pub)
sleep(2)
# 一 发，发公钥
public_key = RSA_D_E.gener_pub_key()  # 生成本地公钥，私钥
print('local public key:', public_key)
sock.send(public_key)  # send public key
sleep(2)
#  二发， 发DES密钥
private_key = open('private.pem', 'rb').read()  # 读取本地私钥
print('local pribate key:', private_key)
DES_key = DES_D_E.gener_DES_key()  # 生成DES随机密钥
print('DES random key:', DES_key)
sock.send(RSA_D_E.encrypt(other_pub, DES_key))  # 将DES密钥通过对方公钥加密，发送
print('send: ', RSA_D_E.encrypt(other_pub, DES_key))
sleep(3)
# 三发 发DES加密后的文件内容
a = DES_D_E.encrypt(message, DES_key)
print('secret file text: ', a)
sock.send(a)
sleep(2)
#  四发，发文件MD5值
print('''file's md5:''', message_md5)
sock.send(RSA_D_E.encrypt(other_pub, message_md5.encode()))
print('send:', RSA_D_E.encrypt(other_pub, message_md5.encode()))
sleep(3)
#  五发，发文件签名
sock.send(RSA_D_E.sig(private_key, md5))
print('RSA file sign:', RSA_D_E.sig(private_key, md5))
print('send:', RSA_D_E.sig(private_key, md5))
sock.close()
