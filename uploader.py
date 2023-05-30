import references.secured_channel.ECDH as ec
from server import authenticate, verify, create_shared_key


def uploader(songs_to_upload: list[str]):
    name = 'Alice'
    print("Alice want to send encrypt message to Bob using LEA in CBC mode with Elliptic Curve Diffie-Hellman key")
    print("Alice generating a private and public Elliptic Curve Diffie-Hellman key")
    alice_secret_key, alice_public_key = ec.make_keypair()
    authenticate_public_key, signature_alice_public_key = authenticate(alice_public_key, alice_secret_key, name)
    verify(authenticate_public_key, alice_public_key, signature_alice_public_key, name)

    print("Alice generating shared keys from the Elliptic Curve Diffie-Hellman key")
    shared_secret = create_shared_key(alice_public_key)

    pass
