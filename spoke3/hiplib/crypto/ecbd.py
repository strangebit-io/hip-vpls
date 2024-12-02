#!/usr/bin/python3

from hiplib.crypto.my_secp256k1 import curve, scalar_mult, point_add, point_neg

import random
from hiplib.utils import misc

#comment again

class ECBD:
    def __init__(self, id):
        self.nr_of_participants = 6
        self.private_key = random.randint(0, curve.n-1)
        self.id = id
        self.z_list = [(0, 0)]*self.nr_of_participants
        self.x_list = [(0, 0)]*self.nr_of_participants
        self._compute_z()

    def _compute_z(self):
        z = scalar_mult(self.private_key, curve.g)
        self.z_list[self.id] = z
        return z
    
    def is_z_list_complete(self):
        return not (0, 0) in self.z_list

    def is_x_list_complete(self):
        return not (0, 0) in self.x_list
    
    def compute_x(self):
        id_next = (self.id + 1) % self.nr_of_participants
        id_prev = (self.id - 1) % self.nr_of_participants

        z_diff = point_add(self.z_list[id_next], point_neg(self.z_list[id_prev]))
        x = scalar_mult(self.private_key, z_diff)
        self.x_list[self.id] = x
        return x

    def compute_k(self):
        n = self.nr_of_participants;

        z_prev = self.z_list[(self.id-1) % n]
        k = scalar_mult(n * self.private_key, z_prev)

        for i in range(n-1):
            x_index = (self.id + i) % n 
            new_term = scalar_mult(n - (i+1), self.x_list[x_index])
            k = point_add(k, new_term)
        
        return k
    
    def _encode_public_list(self, public_list):
        return [b"".join([misc.Math.int_to_bytes_with_len(z[0], 128), 
                misc.Math.int_to_bytes_with_len(z[1], 128)])
                for z in public_list]

    def decode_public_list(self, bytes):
        return misc.Math.bytes_to_int_list(bytes, 128, len(bytes)//256)
    
    def encode_z_list(self):
        return self._encode_public_list(self.z_list)

    def encode_x_list(self):
        return self._encode_public_list(self.x_list)


