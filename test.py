#-*- coding: utf-8 -*-
import base64
import hashlib

import LEA
import random

from references.schnorr_sig.schnorr_lib import sha256
from references.secured_channel.diffie_hellman import *
from references.schnorr_sig import schnorr_lib as sl


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

    F = FiniteField(3851, 1)
    curve = EllipticCurve(a=F(324), b=F(1287))
    base_point = Point(curve, F(920), F(303))

    # Alice's private and public keys
    alice_secret_key = generateSecretKey(256)
    alice_public_key = sendDH(alice_secret_key, base_point, lambda x: x)

    # Bob's private and public keys
    bob_secret_key = generateSecretKey(256)
    bob_public_key = sendDH(bob_secret_key, base_point, lambda x: x)

    # Shared keys
    sharedSecret1 = receiveDH(bob_secret_key, lambda: alice_public_key)
    shared_secret_key_alice = receiveDH(alice_secret_key, lambda: bob_public_key)

    print("Alice encrypts the message with LEA in CBC mode symmetric encryption")
    mp3_filename = r"cha_cha_cha.mp3"

    with open(mp3_filename, 'rb') as f_mp3:
        pt = f_mp3.read()

    #a random 128 bit initial vector
    iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))

    #encryption
    leaCBC = LEA.CBC(True, point_to_bytes(shared_secret_key_alice),iv,True)
    ct = leaCBC.update(pt)
    ct += leaCBC.final()

    print("Alice signs with her secret key using schnorr signature")
    ct_bytes = sha256(ct)
    sig = sl.schnorr_sign(ct_bytes, alice_secret_key)

    print("Alice sends sig and ct to Bob")
    print("Bob verifies the signature")
    s = str(alice_public_key.x.n)
    pubkey_bytes = point_to_bytes(alice_public_key)
    verify = sl.schnorr_verify(ct_bytes, pubkey_bytes, sig)
    if verify:
        print("The signature is VALID for this message and this public key")
        print("Bob decrypts the message that Alice sent")
        leaCBC = LEA.CBC(False, point_to_bytes(sharedSecret1), iv, True)
        pt = leaCBC.update(ct)
        pt += leaCBC.final()

        # Save the encrypted MP3 file to disk
        with open('cha_cha_cha_decrypted.mp3', 'wb') as f:
            f.write(pt)

    else:
        print("The signature is NOT VALID for this message and this public key")

    print("Bob encrypts the LEA key to send to Alice using the Alice public key")

if __name__ == "__main__":
    main()
   