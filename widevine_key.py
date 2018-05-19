#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
import json
import hashlib
import os
import urllib2
from Crypto.Cipher import AES

"""Provider Information"""
PROVIDER_ID = os.environ["PROVIDER_ID"]
PROVIDER_KEY = unhexlify(os.environ["PROVIDER_KEY"])
PROVIDER_IV = unhexlify(os.environ["PROVIDER_IV"])

"""Environment"""
CLOUD_SERVER_URL = os.environ["GET_KEYS_URL"]


def build_message(content_id):
    message = {
        "content_id": b64encode(content_id),
        "tracks": [{"type": "SD"}, {"type": "HD"}, {"type": "AUDIO"}],
        "drm_types": ["WIDEVINE"]
    }
    return json.dumps(message)


def generate_signature(text_to_sign):
    hashed_text = hashlib.sha1(text_to_sign).digest()
    cipher = AES.new(PROVIDER_KEY, AES.MODE_CBC, PROVIDER_IV)
    padding = unhexlify("" if len(hashed_text) % 16 == 0 else (16 - (len(hashed_text) % 16)) * "00")
    aes_msg = cipher.encrypt(hashed_text + padding)
    signature = b64encode(aes_msg)
    return signature


def build_request(content_id):
    message = build_message(content_id)
    request = {
        "request": b64encode(message),
        "signer": PROVIDER_ID,
        "signature": generate_signature(message)
    }
    return json.dumps(request)


def send_request(body):
    try:
        f = urllib2.urlopen(url=CLOUD_SERVER_URL + "/" + PROVIDER_ID, data=body)
    except urllib2.HTTPError as e:
        raise Exception("Invalid key request with code {0} and reason '{1}'".format(e.code, e.reason))
    else:
        return f.read()


def process_response(body):
    response = json.loads(body)
    message = json.loads(b64decode(response['response']))

    if message["status"] == "OK":

        def remove_pssh(track):
            track.pop("pssh", None)
            return track

        def hex_keys(track):
            track["key_id"] = hexlify(b64decode(track["key_id"]))
            track["key"] = hexlify(b64decode(track["key"]))
            return track

        tracks = [hex_keys(remove_pssh(track)) for track in message["tracks"]]
        return json.dumps(message["tracks"], indent=4)
    else:
        raise Exception("Invalid key response with status {0}".format(message["status"]))


def main(argv=None):
    if len(argv) != 2:
        print "Usage: widevine_key <content_id>[hex]"
        return 1

    content_id = unhexlify(argv[1])
    request = build_request(content_id)

    try:
        response = send_request(request)
        key = process_response(response)
    except:
        print "Error retrieving key:", sys.exc_info()[1]
        return 1
    print key
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
