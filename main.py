import os

import elgamal
import rabin
from references.lea.LEA import LEA
from references.lea.CBC import CBC
import random
import base64
import binascii

# if __name__ == "__main__":
#
#     # Generate a random initialization vector
#     iv = os.urandom(16)
#
#     # Choose a secret encryption key
#     key = os.urandom(16)
#
#     # Create a new LEA cipher object in CBC mode
#     cipher = LEA(key, LEA.MODE_CBC, iv)
#
#     # Pad the plaintext to the block size of the LEA algorithm
#     padded_plaintext = pad(plaintext, LEA.block_size)
#
#     # Encrypt the padded plaintext using the LEA cipher in CBC mode
#     ciphertext = cipher.encrypt(padded_plaintext)
#


    #
    # # encryption
    # leaCBC = CBC(True, dec, iv, True)
    # ct = leaCBC.update(plaintext)
    # ct += leaCBC.final()
    #
    # print("\n\nBob encrypted the email successfully using LEA with CBC mode\n")
    # print("Bob send Alice the encrypted email\n")
    #
    # # decryption
    # print("Alice received the encrypted email and she starts decrypting it\n")
    # leaCBC = LEA.CBC(False, dec, iv, True)
    # plaintext = leaCBC.update(ct)
    # plaintext += leaCBC.final()
    #
    # decrypt_output = plaintext.decode('utf8')
    # print("Alice decrypted the email successfully\n")
    # print("The decrypted message is- " + decrypt_output)
    #
    # print("Decrypt End")

    # -*- coding: utf-8 -*-


def main():
    # print("Bob chooses (p,g,a) and publishes it for ALice to use in the El-Gamal EC to encrypt the LEA key")
    # print("Alice uses (p,g,a) to encrypt the LEA key \n")
    # generate key
    keys = elgamal.gen_key(256, 32)
    priv = keys['privateKey']
    pub = keys['publicKey']
    bericht = "blacksnakeblacksnake1234"
    versleuteld = elgamal.encrypt(pub, bericht)
    print("Alice encrypted the key successfully using El-Gamal cipher \n")
    print("Alice choses p and q to sign the key using Rabin signature \n")
    p = 37
    q = 7
    print("Alice choses p = \n", p)
    print("Alice choses q = \n", q)
    if (not rabin.checkPrime(p, q)):
        p = 31
        q = 23

    nRabin = p * q
    resSig, resU = rabin.root(bytes(versleuteld, 'utf-8'), p, q)
    encryp = int.from_bytes(bytes(versleuteld, 'utf-8'), 'big')
    sig2 = resSig ** 2
    print("Alice signed the key successfully using Rabin signature \n")
    print("Alice send bob the encrypted key\n")
    condVerified = (rabin.h(encryp, resU)) % nRabin == ((sig2) % nRabin)
    print("Bob Verifies that the message was received from Alice-->", condVerified)
    if condVerified:
        print("Bob received the encrypted key\n")
        key_bytes = elgamal.decrypt(priv, versleuteld)
        print("Bob decrypted key using El-GAMAL cipher -->", key_bytes)
    else:
        print("None verified message")
    # a random 128 bit initial vector
    # Load the MP3 file into memory
    with open('02 Underground.mp3', 'rb') as f:
        plaintext = f.read()

    iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))
    # encryption
    # key_bytes = b"4b384a376b5c5d3e1f2e3d2c5f6e7d81"
    leaCBC = CBC(True, key_bytes, iv, True)
    ct = leaCBC.update(plaintext)
    ct += leaCBC.final()

    print("\n\nBob encrypted the email successfully using LEA with CBC mode\n")
    print("Bob send Alice the encrypted email\n")

    # decryption
    print("Alice received the encrypted email and she starts decrypting it\n")
    leaCBC = CBC(False, key_bytes, iv, True)
    pt = leaCBC.update(ct)
    pt += leaCBC.final()

    # Save the encrypted MP3 file to disk
    with open('mario_decrypted.mp3', 'wb') as f:
        f.write(pt)
    #
    # print("\n\nBob encrypted the email successfully using LEA with CBC mode\n")
    # print("Bob send Alice the encrypted email\n")
    #
    # # decryption
    # print("Alice received the encrypted email and she starts decrypting it\n")
    # leaCBC = LEA.CBC(False, dec, iv, True)
    # pt = leaCBC.update(ct)
    # pt += leaCBC.final()
    #
    # decrypt_output = pt.decode('utf8')
    # print("Alice decrypted the email successfully\n")
    # print("The decrypted message is- " + decrypt_output)
    #
    # print("Decrypt End")


if __name__ == "__main__":
    main()
