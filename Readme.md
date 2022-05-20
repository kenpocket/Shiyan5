main.py和DES_D_E、GET_Md5、RSA_D_E要在同一目录下


DES_D_E里的方法分别是用来生成随机密钥（gener_DES_key）、加密（encrypt）、解密（decrypt）
RSA_D_E里的方法分别是用来生成密钥对（gener_pub_key）、加密（encrypt）、解密（decrypt）
GET_Md5里用来生成md5值


server.py可以在任意环境内运行，但要满足指定的包条件（如需要安装pycryptodome包）
pip install pycryptodome //windows
pip/pip3 install pycryptodome //linux

