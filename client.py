#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Util import Counter

import rubenesque.curves
from rubenesque.codecs.sec import encode, decode
import hashlib
import sys
import argparse
import json, base64
import socket

# Logging
import logging
import logging.config
logging.config.fileConfig('../logging.conf')
logger = logging.getLogger('client')

# Client variables
private_key = None
secp256r1 = rubenesque.curves.find("secp256r1")

def load_json_from_file(filename):
    with open(filename) as file:
        read_json = json.load(file)
    file.close()

    return read_json

def derive_key(dh_bytes):
    sha256 = hashlib.sha256()
    dh_x = dh_bytes[0:32]
    dh_y = dh_bytes[32:64]
    #sha256.update(dh_str.encode("utf-8"))
    dh_x_int = int.from_bytes(dh_x, byteorder='little')
    dh_x_hex = dh_x.hex()
    logger.debug("feeding sha with")
    logger.debug(dh_x_hex)
    sha256.update(dh_x_hex.encode("utf-8"))
    logger.debug("SHA256")
    logger.debug(sha256.digest())
    return sha256.digest()

def get_ga_from_quote(quote):
    report = quote[48:432]
    ga_xy = report[320:384]
    ga_x = int.from_bytes(ga_xy[0:32], byteorder='big')
    ga_y = int.from_bytes(ga_xy[32:64], byteorder='big')

    ga_x_little = int.from_bytes(ga_xy[0:32], byteorder='little')
    ga_y_little = int.from_bytes(ga_xy[32:64], byteorder='little')

    return (secp256r1(ga_x, ga_y), secp256r1(ga_x_little, ga_y_little))

def gen_dh_keypair():
    b = secp256r1.private_key()
    gb = secp256r1.generator() * b
    return b, gb

def encrypt(pt, key):
    ctr = Counter.new(128)
    ciph = AES.new(key, mode = AES.MODE_CTR, counter = ctr)
    ct = ciph.encrypt(pt.encode("utf-8"))
    return ct

def decrypt(ct, key):
    ctr = Counter.new(128)
    ciph = AES.new(key, mode = AES.MODE_CTR, counter = ctr)
    pt = ciph.decrypt(ct)
    logger.info("Plaintext")
    logger.info(pt)
    return pt

def init_logging(verbose = True):
    """
    Create and set up Logger
    """
    loglevel = (logging.DEBUG if verbose else logging.INFO)
    logger.setLevel(loglevel)
    logger.info("CLIENT for SGX+FaaS")


def parse_args():
    parser = argparse.ArgumentParser(description="SGX+FaaS - Client")
    parser.add_argument(
        "-n", "--net",
        required=False, default=False, action='store_true',
        help="Do the networking only.",
    )
    parser.add_argument(
        "-i", "--input",
        type=str, required=False,
        help="The input file for the client's input. Should contain JSON as cleartext.",
    )
    parser.add_argument(
        "-k", "--keys",
        type=str, required=False,
        help="The public keys together with their quote from the enclave. Given as file path to a JSON file.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str, required=False,
        help="The output file.",
    )
    parser.add_argument(
        "-v", "--verbose",
        required=False, default=False, action='store_true',
        help="Log verbosely.",
    )
    return parser.parse_args()

def read_input(client_file, keys_file):
    client_input = load_json_from_file(client_file)
    logger.info("Client input read from file is:\n%s", client_input)

    logger.info("Reading enclave keys...")
    enclave_keys = load_json_from_file(keys_file)

    enclave_dh = enclave_keys["keys"]["session_dh"]
    ga_x_little = int.from_bytes(base64.b64decode(enclave_dh["gx"]), byteorder='little')
    ga_y_little = int.from_bytes(base64.b64decode(enclave_dh["gy"]), byteorder='little')

    ga = secp256r1(ga_x_little, ga_y_little)
    logger.debug("Enclave DH Key, ga")
    logger.debug(ga)

    return client_input, ga

def produce_keys(ga):
    logger.info("Generating DH keypair (b and gb) and computing shared key")
    privkey, pubkey = gen_dh_keypair()

    # Now output json into enclave
    """
    Json should have structure:
    {
        input: {<encrypted input as read in hello.world.json>},
        gb: <client dh session key>
    }
    of course, we can rename gb, this is just what is used in js.cpp line 106 (input_json["gb"])
    """

    gb_x = int.to_bytes(pubkey.x, length=32, byteorder='little')
    gb_y = int.to_bytes(pubkey.y, length=32, byteorder='little')

    gb_dict = {'gb':
        { 'gx': base64.b64encode(gb_x).decode("utf-8"),
          'gy': base64.b64encode(gb_y).decode("utf-8")}}
    s = json.dumps(gb_dict)
    logger.info("Our pubkey as json: %s", s)

    return privkey, pubkey, gb_dict, s

def do_encryption(client_input, dh):
    dh_bytes = int.to_bytes(dh.x, length=32, byteorder='little') + int.to_bytes(dh.y, length=32, byteorder='little')
    key = derive_key(dh_bytes)[0:16]

    enc_inp = encrypt(client_input, key)

    return enc_inp

def main():
    args = parse_args()
    init_logging(args.verbose)
    if args.net:
        net_main()
        return

    client_input, ga = read_input(args.input, args.keys)

    privkey, pubkey, gb_dict, s = produce_keys(ga)

    dh = ga * privkey
    enc_inp = do_encryption(json.dumps(client_input), dh)
    full_dict = {'input': base64.b64encode(enc_inp).decode("utf-8"), **gb_dict}
    full = json.dumps(full_dict)

    with open(args.output, "wb") as f:
        f.write(full.encode("utf-8"))

    logger.info("Our input to enclave:%s", full)


if __name__ == '__main__':
    main()

def net_process(sock):
    sock.send(b"hello")
    sock.recv(4096)
    print("okay")

def net_main():
    upstream = socket.socket()
    upstream.connect(("localhost", 7000))

    net_process(upstream)
    upstream.close()
