import os

from references.lea.LEA import LEA
from references.lea.CBC import CBC


if __name__ == "__main__":
    # Load the MP3 file into memory
    with open('myfile.mp3', 'rb') as f:
        plaintext = f.read()

    # Generate a random initialization vector
    iv = os.urandom(16)

    # Choose a secret encryption key
    key = os.urandom(16)

    # Create a new LEA cipher object in CBC mode
    cipher = LEA.new(key, LEA.MODE_CBC, iv)

    # Pad the plaintext to the block size of the LEA algorithm
    padded_plaintext = pad(plaintext, LEA.block_size)

    # Encrypt the padded plaintext using the LEA cipher in CBC mode
    ciphertext = cipher.encrypt(padded_plaintext)

    # Save the encrypted MP3 file to disk
    with open('myfile_encrypted.mp3', 'wb') as f:
        f.write(ciphertext)

    #
    # # encryption
    # leaCBC = CBC(True, dec, iv, True)
    # ct = leaCBC.update(pt)
    # ct += leaCBC.final()
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