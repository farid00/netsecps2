#!/usr/bin/python

import os
import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", action='store_true')
    parser.add_argument("-d", action='store_true')
    parser.add_argument("key1")
    parser.add_argument("key2")
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    args = parser.parse_args()
    if args.e:
        handle_encrypt(args)
    elif args.d:
        handle_decrypt(args)


def handle_encrypt(args):
    message = open(args.input_file, 'rb').read()
    public_key = read_public_key_file(args.key1)
    private_key = read_private_key_file(args.key2)
    encrypted_message, key, nonce = aesgcm_encrypt_message_and_sign(
        message, private_key)
    encrypted_key = rsa_encrypt_key(public_key, key)
    encrypted_nonce = rsa_encrypt_key(public_key, nonce)
    compose_file(encrypted_message, encrypted_key,
                 encrypted_nonce, args.output_file)


def handle_decrypt(args):
    public_key = read_public_key_file(args.key2)
    private_key = read_private_key_file(args.key1)
    e_message, e_key, e_nonce = decompose_file(args.input_file)
    d_key = rsa_decrypt_key(private_key, e_key)
    d_nonce = rsa_decrypt_key(private_key, e_nonce)
    d_message = aesgcm_decrypt_message_and_validate(
        e_message, d_key, d_nonce, public_key)
    open(args.output_file, 'wb').write(d_message)


def read_private_key_file(filename):
    extension = filename[-3:]
    key_loader = ""
    if extension == "pem":
        key_loader = serialization.load_pem_private_key
    elif extension == "der":
        key_loader = serialization.load_der_private_key
    else:
        raise Exception("please use a properly formatted"
                        "private key with extension der or pem")
    with open(filename, "rb") as key_file:
        private_key = key_loader(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        return private_key


def read_public_key_file(filename):
    extension = filename[-3:]
    key_loader = ""
    if extension == "pem":
        key_loader = serialization.load_pem_public_key
    elif extension == "der":
        key_loader = serialization.load_der_public_key
    else:
        raise Exception("please use a properly formatted"
                        "public key with extension der or pem")
    with open(filename, "rb") as key_file:
        public_key = key_loader(
            key_file.read(),
            backend=default_backend()
        )
        return public_key


def aesgcm_encrypt_message_and_sign(message, private_key):
    signature = sign_message(message, private_key)
    data = message + "*-*-*-*-*-*" + signature
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return (ct, key, nonce)


def aesgcm_decrypt_message_and_validate(data, key, nonce, public_key):
    aesgcm = AESGCM(key)
    plain_text = aesgcm.decrypt(nonce, data, None)
    data, signature = plain_text.split("*-*-*-*-*-*")
    validate_message(data, signature, public_key)
    return data


def rsa_encrypt_key(public_key, data):
    ct = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ct


def rsa_decrypt_key(private_key, data):
    plain_key = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_key


def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def validate_message(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature as e:
        print("Failure to validate message may have been"
              "tampered with or corrupted in transit: {}").format(e)
        return


def compose_file(em, ek, en, output):
    full_message = "{}*-*-*-*-*-*{}*-*-*-*-*-*{}".format(
        em, ek, en)
    f = open(output, 'wb')
    f.write(full_message)
    f.close()


def decompose_file(filename):
    f = open(filename, 'rb')
    file = f.read()
    em, ek, en = file.split('*-*-*-*-*-*')
    return (em, ek, en)


if __name__ == '__main__':
    main()
