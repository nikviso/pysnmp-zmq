#!/usr/bin/env python3

import base64
import hashlib


def keygen():
    key = ''
    key = hashlib.sha256(key.encode()).digest()
    key_file = open("key_aes","wb")
    key_file.write(base64.b64encode(key))
    key_file.close()


if __name__ == "__main__":
    keygen()
