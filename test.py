#-*- coding: utf-8 -*-
import base64
import hashlib

import LEA
import random

from references.schnorr_sig.schnorr_lib import sha256
from references.secured_channel.diffie_hellman import *
from references.schnorr_sig import schnorr_lib as sl, schnorr_lib

import json
import binascii
import references.schnorr_sig.create_keypair as ckp
import references.schnorr_sig.schnorr_lib as sl

def point_to_bytes(point: Point):
    x_bytes = point.x.n.to_bytes(16, 'big')
    y_bytes = point.y.n.to_bytes(16, 'big')
    return x_bytes + y_bytes


# def main():
#     F = FiniteField(3851, 1)
#     curve = EllipticCurve(a=F(324), b=F(1287))
#     basePoint = Point(curve, F(920), F(303))
#
#     #private
#     aliceSecretKey=generateSecretKey(256)##might be less
#     bobSecretKey=generateSecretKey(256)
#
#     #public
#     alicePublicKey = sendDH(aliceSecretKey, basePoint, lambda x: x)
#     bobPublicKey = sendDH(bobSecretKey, basePoint, lambda x: x)
#
#     message = "chachachaunicorn"
#
#     #shared keys
#     sharedSecret1 = receiveDH(bobSecretKey, lambda: alicePublicKey)
#     sharedSecret2 = receiveDH(aliceSecretKey, lambda: bobPublicKey)
#
#     M = sl.sha256(message.encode())
#
#     sig = sl.schnorr_sign(M, aliceSecretKey)
#     pubkey_bytes = point_to_bytes(alicePublicKey)
#
#     print("PublicKey =", alicePublicKey)
#     print("Signature =", sig.hex())
#
#     result = sl.schnorr_verify(M, pubkey_bytes, sig)
#
#     if result:
#         print("The signature is VALID for this message and this public key")
#     else:
#         print("The signature is NOT VALID for this message and this public key")
#
#     mp3_filename = r"cha_cha_cha.mp3"
#
#     with open(mp3_filename, 'rb') as f_mp3:
#         pt = f_mp3.read()
#
#     #a random 128 bit initial vector
#     iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))
#
#     #encryption
#     leaCBC = LEA.CBC(True, sharedSecret1,iv,True)
#     ct = leaCBC.update(pt)
#     ct += leaCBC.final()
#
#     print("\n\nBob encrypted the email successfully using LEA with CBC mode\n")
#     print("Bob send Alice the encrypted email\n")
#
#     #decryption
#     print("Alice received the encrypted email and she starts decrypting it\n")
#     leaCBC = LEA.CBC(False, dec,iv, True)
#     pt = leaCBC.update(ct)
#     pt += leaCBC.final()
#
#     # Save the encrypted MP3 file to disk
#     with open('cha_cha_cha_decrypted.mp3', 'wb') as f:
#         f.write(pt)
#
#
#    # decrypt_output = pt.decode()
#     print("Alice decrypted the email successfully\n")
#    # print("The decrypted message is- " + decrypt_output)
#
#     print("Decrypt End")

def main():
    print("Alice want to send encrypt message to Bob using LEA in CBC mode with Elliptic Curve Diffie-Hellman key")
    print("Alice generating a private and public Elliptic Curve Diffie-Hellman key")

    #base_point = Point(curve, F(920), F(303))
    # [0] - Alice's public key, [1] Bob's public key
    public_keys_list = ckp.create_keypair()

    filename = "users.json"
    with open(filename, "r") as file:
        data = json.load(file)
    alice_secret_key = data['users'][0]['privateKey']
    alice_public_key = data['users'][0]['publicKey']

    bob_secret_key = data['users'][1]['privateKey']
    bob_public_key = data['users'][1]['publicKey']

    # Shared keys
    shared_secret_key_bob = receiveDH(bob_secret_key, lambda: public_keys_list[0]) # 0 - Alice, 1 - Bob
    shared_secret_key_alice = receiveDH(alice_secret_key, lambda: public_keys_list[1])

    print("Alice encrypts the message with LEA in CBC mode symmetric encryption")
    mp3_filename = r"cha_cha_cha.mp3"

    # with open(mp3_filename, 'rb') as f_mp3:
    #    pt = f_mp3.read()
    pt = mp3_filename
    #a random 128 bit initial vector
    iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))

    #encryption
    string_value = str(shared_secret_key_alice.x.n)
    bytes_value = string_value.encode('utf-8')

    leaCBC = LEA.CBC(True, point_to_bytes(shared_secret_key_alice),iv,True)
    ct = leaCBC.update(pt)
    ct += leaCBC.final()

    print("Alice signs with her secret key using schnorr signature")
    ct_bytes = sha256(ct)
    #changed int.to_bytes(alice_secret_key)
    hex_privkey = hex(alice_secret_key).replace('0x', '').rjust(64, '0')
    sig = sl.schnorr_sign(ct_bytes, hex_privkey)

    print("Alice sends sig and ct to Bob")
    print("Bob verifies the signature")
    #3s = str(alice_public_key.x.n)

    pubkey_bytes = bytes.fromhex(alice_public_key)
    verify = sl.schnorr_verify(ct_bytes, pubkey_bytes, sig)
    if verify:
        print("The signature is VALID for this message and this public key")
        print("Bob decrypts the message that Alice sent")
        leaCBC = LEA.CBC(False, point_to_bytes(shared_secret_key_bob), iv, True)
        pt = leaCBC.update(ct)
        pt += leaCBC.final()

        # Save the encrypted MP3 file to disk
        with open('cha_cha_cha_decrypted.mp3', 'wb') as f:
            f.write(pt)

    else:
        print("The signature is NOT VALID for this message and this public key")

if __name__ == "__main__":
    main()
   