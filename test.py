#-*- coding: utf-8 -*-
import LEA
import elgamal
import rabin
import random
import base64
from references.secured_channel.elliptic import *
from references.secured_channel.finitefield.finitefield import FiniteField
from references.secured_channel.diffie_hellman import *
from references.schnorr_sig import schnorr_lib as sl
from references.schnorr_sig import create_keypair as ckp
import os


def point_to_bytes(point: Point):
    x_bytes = point.x.n.to_bytes(16, 'big')
    y_bytes = point.y.n.to_bytes(16, 'big')
    return x_bytes + y_bytes


def main():
    F = FiniteField(3851, 1)
    curve = EllipticCurve(a=F(324), b=F(1287))
    basePoint = Point(curve, F(920), F(303))

    print("Bob chooses (p,g,a) and publishes it for ALice to use in the El-Gamal EC to encrypt the LEA key")
    print("Alice uses (p,g,a) to encrypt the LEA key \n")
    #keys = elgamal.gen_key(256, 32)
    #generateSecretKey(256) 256 bits
    #read vals
    #priv = keys['privateKey']#!!!!!!!!!!!!!!!!!!!!!!!!!
    #pub = keys['publicKey']#!!!!!!!!!!!!!!!!!!!!!!!!!

    #private
    aliceSecretKey=generateSecretKey(256)##might be less
    bobSecretKey=generateSecretKey(256)

    #public
    alicePublicKey = sendDH(aliceSecretKey, basePoint, lambda x: x)
    bobPublicKey = sendDH(bobSecretKey, basePoint, lambda x: x)

    message = "chachachaunicorn"
    #M = elgamal.encrypt(bobSecretKey, message)#SC !!!!!!!!!!!!!!!!!!!!!

    #shared keys
    sharedSecret1 = receiveDH(bobSecretKey, lambda: alicePublicKey)
    sharedSecret2 = receiveDH(aliceSecretKey, lambda: bobPublicKey)

    M = sl.sha256(message.encode())

    sig = sl.schnorr_sign(M, aliceSecretKey)
    pubkey_bytes = point_to_bytes(alicePublicKey)

    print("PublicKey =", alicePublicKey)
    print("Signature =", sig.hex())

    result = sl.schnorr_verify(M, pubkey_bytes, sig)

    if result:
        print("The signature is VALID for this message and this public key")
    else:
        print("The signature is NOT VALID for this message and this public key")


    # print("Alice encrypted the key successfully using El-Gamal cipher \n")
    # print("Alice choses p and q to sign the key using Rabin signature \n")
    # p = 37
    # q = 7
    # print("Alice choses p = \n" ,p)
    # print("Alice choses q = \n", q)
    # #if (not rabin.checkPrime(p,q)):#prime for sig
      #p = 31
      #q = 23
    # p=sharedSecret1
    # q=sharedSecret2
    # nRabin = p*q#sig
    # resSig, resU = rabin.root(bytes(M,'utf-8'),p,q)#sig
    # encryp = int.from_bytes(bytes(M,'utf-8'),'big')
    # sig2 = resSig**2#sig
    # print("Alice signed the key successfully using Rabin signature \n")
    # print("Alice send bob the encrypted key\n")
    # condVerified = (rabin.h(encryp,resU)) % nRabin == ((sig2)% nRabin)#sig ver
    # print("Bob Verifies that the message was received from Alice-->", condVerified)
    # if condVerified:
    #   print("Bob received the encrypted key\n")
    #   dec = elgamal.decrypt(aliceSecretKey, M)#shared key !!!!!!!!!!!!!!!!!
    #   print("Bob decrypted key using El-GAMAL cipher -->", dec)
    # else:
    #   print("None verified message")
    # print("and he start to encrypt the email message with this key\n")


# ===========================================

   #
   #
   #  mp3_filename = r"cha_cha_cha.mp3"
   #
   #  with open(mp3_filename, 'rb') as f_mp3:
   #      pt = f_mp3.read()
   #
   #  #a random 128 bit initial vector
   #  iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))
   #
   #  #encryption
   #  leaCBC = LEA.CBC(True, dec,iv,True)
   #  ct = leaCBC.update(pt)
   #  ct += leaCBC.final()
   #
   #  print("\n\nBob encrypted the email successfully using LEA with CBC mode\n")
   #  print("Bob send Alice the encrypted email\n")
	#
   #  #decryption
   #  print("Alice received the encrypted email and she starts decrypting it\n")
   #  leaCBC = LEA.CBC(False, dec,iv, True)
   #  pt = leaCBC.update(ct)
   #  pt += leaCBC.final()
   #
   #  # Save the encrypted MP3 file to disk
   #  with open('cha_cha_cha_decrypted.mp3', 'wb') as f:
   #      f.write(pt)
   #
   #
   # # decrypt_output = pt.decode()
   #  print("Alice decrypted the email successfully\n")
   # # print("The decrypted message is- " + decrypt_output)
   #
   #  print("Decrypt End")


if __name__ == "__main__":
    main()
   