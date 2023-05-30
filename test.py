# -*- coding: utf-8 -*-
import base64
import LEA
import random
import references.secured_channel.ECDH as ec
import schnorr
from binascii import hexlify


def create_verifier(public_key, p, g):
    verifier = schnorr.SchnorrVerifier(keys=public_key, p=p, g=g, hash_func=schnorr.sha256_hash)
    return verifier


def main():
    print("Alice want to send encrypt message to Bob using LEA in CBC mode with Elliptic Curve Diffie-Hellman key")
    print("Alice generating a private and public Elliptic Curve Diffie-Hellman key")

    # Create private and public key for Alic and Bob
    aliceSecretKey, alicePublicKey = ec.make_keypair()
    bobSecretKey, bobPublicKey = ec.make_keypair()

    g = 2
    p = 2695139  # prime number
    public_key = pow(g, aliceSecretKey, p)
    signer = schnorr.SchnorrSigner(key=aliceSecretKey, p=p, g=g, hash_func=schnorr.sha256_hash)
    print("Alice signs the public key")
    signature_alice_public_key = signer.sign(str(alicePublicKey))

    print("Bob verifies that he talk with Alice")
    Bob_verifier = create_verifier(public_key, p, g)
    verified = Bob_verifier.verify(str(alicePublicKey), signature_alice_public_key)
    if verified:
        print("Bob verified alice's public key")
    else:
        print("Abort. The signature of the public key is NOT VALID.")
        raise Exception("Imposter captured")

    print("Alice generating shared keys from the Elliptic Curve Diffie-Hellman key")
    # Calculate shared key - DH
    shared_secret1 = ec.scalar_mult(bobSecretKey, alicePublicKey)
    shared_secret2 = ec.scalar_mult(aliceSecretKey, bobPublicKey) # No need, it's suppose to be the same like sharedSecert1
    if shared_secret1 == shared_secret2:
        print("The shared keys are the same. Continue to encrypt.")

    print("Alice encrypts the message with LEA in CBC mode symmetric encryption")
    mp3_filename = r"cha_cha_cha.mp3"

    with open(mp3_filename, 'rb') as f_mp3:
       pt = f_mp3.read()
    # a random 128 bit initial vector
    iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))

    # encryption
    shared_key_str = str(shared_secret1[0])
    shared_key_bytes = bytes(shared_key_str, 'ascii')
    shared_lea_key = hexlify(shared_key_bytes)
    shared_lea_key = shared_lea_key[0:24]

    leaCBC = LEA.CBC(True, shared_lea_key, iv, True)
    ct = leaCBC.update(pt)
    ct += leaCBC.final()

    print("Alice signs with her secret key using schnorr signature of the cipher text")
    signer = schnorr.SchnorrSigner(key=aliceSecretKey, p=p, g=g, hash_func=schnorr.sha256_hash)
    signature = signer.sign(str(ct))

    print("Alice sends signature of the ct to Bob")
    print("Bob verifies the signature")
    verified = Bob_verifier.verify(str(ct), signature)
    if verified:
        print("The signature is VALID for this message and this public key")
        print("Bob decrypts the message that Alice sent")
        leaCBC = LEA.CBC(False, shared_lea_key, iv, True)
        pt = leaCBC.update(ct)
        pt += leaCBC.final()

        # Save the encrypted MP3 file to disk
        with open('cha_cha_cha_decrypted.mp3', 'wb') as f:
            f.write(pt)
    else:
        print("The signature is NOT VALID for this message and this public key")



if __name__ == "__main__":
    main()