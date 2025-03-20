##python 3.12.0

import argparse
import math

def general_switch(text,forum):#通用矩阵置换方法
    switched_text = ''
    for i in range(1,len(forum)+1):
        switched_char = text[forum[i-1]-1]
        switched_text += switched_char
    return switched_text

def init_switch(cipher):#对明文：初始置换
    switch_IP=(58,50,42,34,26,18,10,2,
               60,52,44,36,28,20,12,4,
               62,54,46,38,30,22,14,6,
               64,56,48,40,32,24,16,8,
               57,49,41,33,25,17, 9,1,
               59,51,43,35,27,19,11,3,
               61,53,45,37,29,21,13,5,
               63,55,47,39,31,23,15,7)
    cipher = general_switch(cipher,switch_IP)
    return cipher
    
def init_switch_alt(cipher):#对明文：逆初始置换
    switch_IP_alt=(40,8,48,16,56,24,64,32,
                   39,7,47,15,55,23,63,31,
                   38,6,46,14,54,22,62,30,
                   37,5,45,13,53,21,61,29,
                   36,4,44,12,52,20,60,28,
                   35,3,43,11,51,19,59,27,
                   34,2,42,10,50,18,58,26,
                   33,1,41, 9,49,17,57,25)
    cipher = general_switch(cipher,switch_IP_alt)
    return cipher

def switch_choose_1(secret):#对秘钥：选择置换1
    PC_1=(57,49,41,33,25,17, 9,
           1,58,50,42,34,26,18,
          10, 2,59,51,43,35,27,
          19,11, 3,60,52,44,36,
          63,55,47,39,31,23,15,
           7,62,54,46,38,12,22,
          14, 6,61,53,45,37,29,
          21,13, 5,28,20,30, 4)
    for i in range(len(secret),1,-1):#扩展56位秘钥至64位
        if i%7==0:
            secret = list(secret)
            secret.insert(i,'9')#位于8的倍数的位置用9填充
    secret = "".join(secret)
    secret = general_switch(secret,PC_1)
    secret = secret.replace('9','')#置换完成后去掉'9'
    return secret


def switch_choose_2(secret):#对秘钥：选择置换2
    PC_2=(14,17,11,24, 1, 5,
           3,28,15, 6,21,10,
          23,19,12, 4,26, 8,
          16, 7,27,20,13, 2,
          41,52,31,37,47,55,
          30,40,51,45,33,48,
          44,49,39,56,34,53,
          46,42,50,36,29,32)
    secret = general_switch(secret,PC_2)
    return secret

def left_move(secret,time):
    #加密时使用前16位，解密时用后16位
    schedule=(1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1,0,27,26,26,26,26,26,26,27,26,26,26,26,26,26,27)
    for i in range(0,schedule[time-1]):
        new_secret=''
        for char in secret[1:]:
            new_secret += char
        secret=new_secret+secret[0]
    return secret

def extention_switch(cipher):#对明文：扩展置换
    E=(32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9,10,11,12,13,
       12,13,14,15,16,17,
       16,17,18,19,20,21,
       20,21,22,23,24,25,
       24,25,26,27,28,29,
       28,29,30,31,32, 1)
    cipher = general_switch(cipher,E)
    return cipher

def xor(a,b):#按 bit 异或操作
    c=''
    for i in range(0,len(a)):
       c_char = str(int(a[i]) ^ int(b[i]))
       c += c_char
    return c

def Sbox_switch_part(slice,S):#S盒置换操作：输入6位，输出4位
    choice = S[int(slice[0]) * 2 + int(slice[5]) - 1][int(slice[1]) * 8 + int(slice[2]) * 4 + int(slice[3]) * 2 + int(slice[4]) - 1]
    first = choice // 8
    second = (choice - 8 * first) // 4
    third = (choice - 8 * first - 4 * second) // 2
    forth = choice % 2
    part = str(first) + str(second) + str(third) + str(forth)
    return part

def Sbox_switch(cipher):#S盒置换：分派S盒
    S_1 = ((14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7),
           ( 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8),
           ( 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0),
           (15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13))
    S_2 = ((15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10),
           ( 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5), 
           ( 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15),
           (13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9))
    S_3 = ((10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8),
           (13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1),
           (13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7),
           ( 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12))
    S_4 = (( 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15),
           (13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9),
           (10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4),
           ( 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14))
    S_5 = (( 2,12, 4, 1, 7,10,11, 6, 5, 8, 3,15,13, 0,14, 9),
           (14,11, 2,12, 4, 7,13, 1, 5, 0,15,13, 3, 9, 8, 6),
           ( 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14),
           (11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3))
    S_6 = ((12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11),
           (10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8),
           ( 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6),
           ( 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13))
    S_7 = (( 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1),
           (13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6),
           ( 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2),
           ( 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12))
    S_8 = ((13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7),
           ( 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2),
           ( 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8), 
           ( 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11))
    S = (S_1,S_2,S_3,S_4,S_5,S_6,S_7,S_8)#将所有 S 盒存放于 S 元组中，方便循环调用
    crypted = ''
    for i in range(1,9):
        crypted += Sbox_switch_part(cipher[(6 * i - 6) : (6 * i)],S[i - 1])
    return crypted

def P_switch(cipher):#P 置换
    P = (16, 7,20,21,
         29,12,28,17,
          1,15,23,26,
          5,18,31,10,
          2, 8,24,14,
         32,27, 3, 9,
         19,13,30, 6,
         22,11, 4,25)
    cipher = general_switch(cipher,P)
    return cipher

def crypt(cipher_l,cipher_r,K):#在 Rn-1 和 Rn 之间的加/解密
    
    #扩展置换
    cipher_r = extention_switch(cipher_r)

    #与k取异或
    cipher_r = xor(cipher_r,K)

    #S盒 代换/选择
    cipher_r = Sbox_switch(cipher_r)

    #P置换
    cipher_r = P_switch(cipher_r)

    #lr异或
    cipher_r = xor(cipher_l,cipher_r)

    return cipher_r

def Feistel(fore_cipher_l,fore_cipher_r,secret_l,secret_r,time,mode):#Feistel 结构加/解密
    
    if mode == 'encrypt':
        #秘钥左循环移位
        secret_c=left_move(secret_l,time)
        secret_d=left_move(secret_r,time)
        secret=secret_c+secret_d
    else:
        #秘钥左循环移位
        secret_c=left_move(secret_l,time+16)
        secret_d=left_move(secret_r,time+16)
        secret=secret_c+secret_d
    
    #秘钥置换选择2
    secret=switch_choose_2(secret)
    print('生成子密钥',(time - 1) %16 + 1,':',secret)
    
    #加密/解密
    if mode == 'encrypt':
        cipher_l = fore_cipher_r
        cipher_r = crypt(fore_cipher_l,fore_cipher_r,secret)
    else:
        cipher_r = fore_cipher_l
        cipher_l = crypt(fore_cipher_r,fore_cipher_l,secret)

    return cipher_l,cipher_r,secret_c,secret_d

def hex_to_bin(string,mode):#二进制与十六进制之间相互转换
    string = string.lower()
    hex = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    bin = ['0000','0001','0010','0011','0100','0101','0110','0111','1000','1001','1010','1011','1100','1101','1110','1111']
    new_string=''
    if mode == 1:#1模式为十六进制转二进制
        for char in string:
            new_string += bin[hex.index(char)]
    elif mode == 0:#0模式为二进制转十六进制
          for i in range(0,len(string)//4):
              char = string[4*i:4*i+4]
              new_string += hex[bin.index(char)]
    string =new_string
    return string

#检查输入合法性
def input_check(inputs,nums,scale):
    #检查2进制字符串合法性
    if scale == 2:
        for i in inputs:#检查输入内容
                if i !='0' or '1':
                    print("存在非2进制字符:",i)
                    return False
    #检查16进制字符串合法性
    else:
        hexes = {'a','b','c','d','e','f','A','B','C','D','E','F'}
        for i in inputs:#检查输入内容
                if i.isdigit()==False and i not in hexes:
                    print("存在非16进制字符:",i)
                    return False
    return True

def args_check(args):#检查输入参数合法性
    scale = args.scale
    mode = str(args.mode)
    
    if scale != 16 and scale !=2 :
        print("scale 只接受2进制或16进制字符串, 输入非法参数: ",scale)
        return False
    
    if mode != 'encrypt' and mode != 'decrypt' :
        print("mode 只接受 encrypt 模式或 decrypt 模式, 输入非法参数: ",mode)
        return False
    
    return True

def fix(string,nums,scale):
    while len(string)%(nums//int(math.log(scale,2)))!=0:
        string += '0'
    return string

def inputs():
    #接受输入明文进制、加解密模式
    parser = argparse.ArgumentParser()
    parser.add_argument("--scale", type=int,default=16, help="accept 2 or 16 numeration")
    parser.add_argument("--mode", type=str,default='encrypt', help="encrypt or decrypt")
    args = parser.parse_args()
    scale = args.scale
    mode = str(args.mode)

    #检查输入参数合法性
    if args_check(args)==False:
        exit()

    #输入明文与秘钥并检查合法性
    texts = input("输入 64bit 或最好是其倍数长度的明文/密文: ")
    
    while input_check(texts,64,scale)==False:
        texts = input("明文/密文输入不合法，重新输入: ")
    
    keys = input("输入 56bit 或最好是其倍数长度的秘钥: ")
    while input_check(keys,56,scale)==False:
        keys=input("秘钥输入不合法，重新输入: ")
    
    #补全
    texts = fix(texts,64,scale)
    keys = fix(keys,56,scale)

    print('实际采用明文/密文: ',texts)
    print('实际采用秘钥: ',keys)

    results = ''

    #将输入的十六进制字符转换为二进制字符处理
    if scale == 16:
      texts = hex_to_bin(texts,True)
      keys = hex_to_bin(keys,True)

    for num in range(0,len(texts)//64):
        text = texts[64*num:64*num+64]
        key = keys[(56 * num) % len(keys):(56 * num + 55) % len(keys) + 1]
        
        print('第',num+1,'组加解密采用明文/密文段:',text,'即',hex_to_bin(text,False))
        print('第',num+1,'组加解密采用秘钥段:',key,'即',hex_to_bin(key,False))
        
        #明文初始置换
        text=init_switch(text)

        #秘钥置换选择
        key=switch_choose_1(key)

        #16轮 Feistel
        for i in range(1,17):
            result = Feistel(text[:32],text[32:],key[:28],key[28:],i,mode)
            text = result[0] + result[1]
            key = result[2] + result[3]
    
        #逆初始置换
        text = init_switch_alt(text)
    
        if scale == 16:#若输入数据为十六进制，则将结果转换为十六进制输出
            text = hex_to_bin(text,False)
    
        if mode =='encrypt':
            print('对第',num+1,'组明文加密后: ',text)
        else:
            print('对第',num+1,'组密文解密后: ',text)
        results += text

    print('最终结果为:',results)

def main():
    inputs()
    
if __name__ == '__main__':
    main()
