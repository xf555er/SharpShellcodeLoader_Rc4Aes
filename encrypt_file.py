#!/usr/bin/python3

import sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import ARC4
from base64 import b64encode, b64decode
import string
import os
import secrets

"""
Requirements:
Must have pycryptodome installed.
Install examples:
python3 -m pip install pycryptodome
"""

# 生成32位的密钥
def generate_key():
    alphabet = string.ascii_letters + string.digits  # 包括大小写字母和数字
    return ''.join(secrets.choice(alphabet) for i in range(32))

# aes加密函数
def aes_encrypt(message, key, key_size=256):
    # 对信息进行填充
    message = pad(message, AES.block_size, style='pkcs7')
    # 生成随机的初始化向量(IV)
    iv = Random.new().read(AES.block_size)
    # 创建一个新的AES加密对象
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    # 返回加密后的信息，信息的开头是IV
    return iv + cipher.encrypt(message)

# aes解密函数
def aes_decrypt(ciphertext, key):
    # 从密文中提取初始化向量(IV)
    iv = ciphertext[:AES.block_size]
    # 创建一个新的AES解密对象
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    # 使用AES解密密文，并去除填充
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size, style='pkcs7')
    return plaintext

# aes加密文件
def aes_encrypt_file(key, in_file, out_file):
    # 打开并读取输入文件的内容
    with open(in_file, 'rb') as fo:
        plaintext = fo.read()
    # 使用AES加密这些内容
    enc = aes_encrypt(plaintext, key)
    # 将加密后的内容写入输出文件
    with open(out_file, 'wb') as fo:
        fo.write(enc)
    print(f'[*] Read File Bytes: {len(plaintext)}')
    print(f'[*] AES Encrypted File Bytes: {len(enc)}')
    print("[*] AES encrypted file written to: " + out_file)

# aes解密文件
def aes_decrypt_file(key, in_file, out_file):
    with open(in_file, 'rb') as fo:
        ciphertext = fo.read()
    #ciphertext = b64decode(ciphertext)
    dec = aes_decrypt(ciphertext, key)
    #dec = b64decode(dec)
    with open(out_file, 'wb') as fo:
        fo.write(dec)
    print(f'[*] Read File Bytes: {len(ciphertext)}')
    print(f'[*] AES Decrypted File Bytes: {len(dec)}')
    print("[*] AES decrypted file written to: " + out_file)

# rc4加密文件
def rc4_encrypt_file(key, in_file, out_file):
    # 打开并读取输入文件的内容
    with open(in_file, 'rb') as fo:
        plaintext = fo.read()
    # 创建一个新的RC4加密对象
    cipher = ARC4.new(key.encode('utf-8'))
    # 使用RC4加密这些内容
    enc = cipher.encrypt(plaintext)
    # 将加密后的内容写入输出文件
    with open(out_file, 'wb') as fo:
        fo.write(enc)
    print(f'[*] Read File Bytes: {len(plaintext)}')
    print(f'[*] RC4 Encrypted File Bytes: {len(enc)}')
    print("[*] RC4 encrypted file written to: " + out_file)

# rc4解密文件
def rc4_decrypt_file(key, in_file, out_file):
    # 打开并读取输入文件的密文内容
    with open(in_file, 'rb') as fo:
        ciphertext = fo.read()
    # 创建一个新的RC4解密对象
    cipher = ARC4.new(key.encode('utf-8'))
    # 使用RC4进行解密，因为RC4是对称加密算法，所以加密和解密方法相同
    dec = cipher.encrypt(ciphertext)
    # 将解密后的内容写入输出文件
    with open(out_file, 'wb') as fo:
        fo.write(dec)
    print(f'[*] Read File Bytes: {len(ciphertext)}')
    print(f'[*] RC4 Decrypted File Bytes: {len(dec)}')
    print("[*] RC4 decrypted file written to: " + out_file)


if __name__ == '__main__':

    key = generate_key()
    print(f"Generated Key: {key}")

    if len(sys.argv) != 4:
        print('Usage: encrypt_file.py <aes/rc4> <encrypt/decrypt> <input file>')
    else:
        mode = sys.argv[1]
        operation = sys.argv[2]
        input_file = sys.argv[3]
        output_file = os.path.join(os.path.dirname(input_file), f"encrypt_{os.path.basename(input_file)}")

        if mode == 'aes' and operation == 'encrypt':
            aes_encrypt_file(key, input_file, output_file)
        elif mode == 'aes' and operation == 'decrypt':
            aes_decrypt_file(key, input_file, output_file)
        elif mode == 'rc4' and operation == 'encrypt':
            rc4_encrypt_file(key, input_file, output_file)
        elif mode == 'rc4' and operation == 'decrypt':
            rc4_decrypt_file(key, input_file, output_file)

