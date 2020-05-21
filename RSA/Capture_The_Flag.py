#!/usr/bin/python3

import re
import os
from math import gcd
from binascii import unhexlify


"""Project CTF
   Flag is 'b4dly_0pt1m12ed_RSA'
   @author Tomer Fisher 205364151"""

def memoize(f):
    memory = {}

    def helper(a, m):
        if (a, m) not in memory:
            memory[(a, m)] = f(a, m)
        return memory[(a, m)]

    return helper


@memoize# Extended Euclidean algorithm
def gcdExtended(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1

    g, x1, y1 = gcdExtended(b % a, a)

    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1

    return g, x, y

"""Object that hold the every info of file - modulus and secret message"""
class Msg_Obj:

    def __init__(self, file, file_num):
        self.modulus = file.readline().lstrip("Modulus:").strip()
        self.encrypted_msg = file.readline().replace("Secret Message:", "").strip()
        self.decrypted_msg = 0
        self.p = None
        self.q = None
        self.d = None
        self.file_num = file_num
        self.bin = ''

    def get_d(self):
        return self.d

    def set_decrypted_msg(self, msg):
        self.decrypted_msg = msg

    def set_p(self, p):
        self.p = p

    def set_q(self, q):
        self.q = q

    def get_n(self):
        return self.p * self.q

    def calculate_d(self, p, q, e):
        phi = (p-1)*(q-1)
        self.d = gcdExtended(e, phi)[1]%phi

    def to_dec(self):
        return int(self.modulus, 16), int(self.encrypted_msg, 16)

    def get_file_num(self):
        return self.file_num

    def get_modulus(self):
        return self.modulus

    def get_encrypted_msg(self):
        return self.encrypted_msg

###########################################################################


class RSA:

    def __init__(self):
        self.directory = os.path.join(os.getcwd(), "intercepted")
        self.e = 65537
        self.messages_paths = self.__msg_path()
        self.msg_arr = []
        self.flag = ''
        self.msg_flag_num = 0

####################################################################################
    """function that loop over directory and get the path of every txt file in it"""
    def __msg_path(self):
        return [os.path.join(self.directory, file) for file in os.listdir(self.directory)]
####################################################################################
    """read all info from every txt and create an object for it"""
    def readAllinfo(self):
        for index, file in enumerate(self.messages_paths):
            with open(file, "r") as f:
                self.msg_arr.append(Msg_Obj(f, index))

####################################################################################
    """ find p and q and store it in Msg_Obj members
    calculate d."""
    def find_p_q(self):
        for msg_1 in self.msg_arr:
            for msg_2 in self.msg_arr[-1:msg_1.file_num:-1]:
                if msg_1.d is not None and msg_2.d is not None:
                    continue
                modulus_i, modulus_j = [msg_1.to_dec()[0], msg_2.to_dec()[0]]
                if modulus_i == modulus_j:
                    continue
                p = gcd(modulus_i, modulus_j)
                if p != 1:
                    q1, q2 = modulus_i // p, modulus_j // p
                    msg_1.set_p(p)
                    msg_1.set_q(q1)
                    msg_2.set_p(p)
                    msg_2.set_q(q2)
                    msg_1.calculate_d(p, q1, self.e)
                    msg_2.calculate_d(p, q2, self.e)

#######################################################################################
    def capture_the_flag(self):
        for msg in self.msg_arr:
            if msg.get_d() is not None:
                c, d, n = msg.to_dec()[1], msg.get_d(), msg.get_n()
                m = pow(c, d, n)
                c = unhexlify(hex(m)[2:]).decode("utf-8")
                place = unhexlify(hex(m)[2:]).decode("utf-8")
                place = re.search("flag{(.*)}", place)
                if place:
                    self.flag = place.group(1)
                    self.msg_flag_num = msg.file_num
                    print(f"The flag is: {self.flag}\nfounded in message: {self.msg_flag_num}")
                    return

#######################################################################################

def main():
    rsa = RSA()
    rsa.readAllinfo()# get all info from every file(modulus and encrypted msg).
    rsa.find_p_q()
    rsa.capture_the_flag()


if __name__ == "__main__":
    main()