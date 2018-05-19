#!/usr/bin/python
# -*- encoding: utf-8 -*-

from base64 import b64encode, b64decode
import json
import logging
import os
import ast
from binascii import hexlify, unhexlify
import sys
import urllib2
import urlparse
import webapp2
import hashlib
from Crypto.Cipher import AES
from paste import httpserver
from OpenSSL import SSL

"""Provider information"""

PROVIDER_ID = os.environ["PROVIDER_ID"]
PROVIDER_KEY = unhexlify(os.environ["PROVIDER_KEY"])
PROVIDER_IV = unhexlify(os.environ["PROVIDER_IV"])

"""GetLicense URL"""

LICENSE_SERVER_URL = os.environ["GET_LICENSE_URL"]

"""Setup Console Logging."""
_LOG = logging.getLogger("widevine_proxy")
_LOG.setLevel(logging.DEBUG)
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
consoleHandler.setFormatter(formatter)
_LOG.addHandler(consoleHandler)

"""Setup File Logging."""
'''
fileHandler = logging.FileHandler('/var/log/widevine_proxy.log')
fileHandler.setLevel(logging.DEBUG)
fileHandler.setFormatter(formatter)
_LOG.addHandler(fileHandler)
'''

# TO-DO: add array of keyid, content_id
KMS = {
    os.environ["CONTENT_ID"]: (os.environ["KEY_ID"], os.environ['CONTENT_KEY']),
    "rd61a3e510544cdb811767349247ffe0": ("tg51a3e510566cyhb8115677849a67afe2", "N2458F0F73BB7BE74B4C51A973C46998")
}
sessions = []


class proxyHandler(webapp2.RequestHandler):
    """Proxy handler for Modular DRM"""

    def post(self):
        if self.request.body is None:
            _LOG.debug("Empty request")
            return None

        self.response.headers['Access-Control-Allow-Methods'] = 'POST'
        self.response.headers['Access-Control-Allow-Credentials'] = 'true'
        if self.request.referer is None:
            self.response.headers['Access-Control-Allow-Origin'] = '*'
        else:
            referer = urlparse.urlparse(self.request.referer)
            self.response.headers['Access-Control-Allow-Origin'] = '{0}://{1}'.format(referer.scheme, referer.hostname)

        try:
            if (sys.getsizeof(b64encode(self.request.body)) < 50):
                response = self.send_request(self.build_certificate_request())
                status_ok, response = self.process_certificate_response(response)
            else:
                response = self.send_request(self.build_parse_only_request())
                content_id = self.process_parse_only_response(response)
                #  token = self.request.headers['X-Auth-Token']
                allow = self.apply_bussiness_rules(content_id, token=None)
                if allow:
                    response = self.define_license_request_type(content_id)
                else:
                    os.environ["CAN_PLAY"] = "False"
                    response = self.define_license_request_type(content_id)
                    os.environ["CAN_PLAY"] = "True"
                status_ok, response = self.process_license_response(response)

            if status_ok:
                #  Sends response to Player
                self.response.write(response)
            else:
                self.send500(response)
        except TypeError:
            self.send400("Invalid License Request")

    def define_license_request_type(self, content_id):
        if os.environ["EXTERNAL_KEYS"] == "false":
            # create content_key_specs with the keys of KMS
            if content_id:
                content_key_specs = self.retrieve_content_key_specs(content_id)
                response = self.send_request(self.build_license_request(content_id, content_key_specs))
            else:
                response = self.send_request(self.build_license_request())
        else:
            response = self.send_request(self.build_license_request(content_id))

        return response

    def build_certificate_request(self):
        message = self.build_certificate_message()
        request = b64encode(message)
        signature = self.generate_signature(message)
        certificate_request = {"request": request,
                               "signature": signature,
                               "signer": PROVIDER_ID}
        return json.dumps(certificate_request)

    def build_certificate_message(self):
        """Build a certificate request to be sent to Widevine Service."""
        payload = b64encode(self.request.body)
        request = {"payload": payload}
        _LOG.debug("Certificate Request: {}".format(json.dumps(request, indent=4)))
        return json.dumps(request)

    def build_license_request(self, content_id=None, content_key_specs=None):
        message = self.build_license_message(content_id, content_key_specs)
        request = b64encode(message)
        signature = self.generate_signature(message)
        license_info_request = json.dumps({"request": request,
                                           "signature": signature,
                                           "signer": PROVIDER_ID})
        return license_info_request

    def build_license_message(self, content_id, content_key_specs):
        """Build a license request to be sent to Widevine Service."""
        payload = b64encode(self.request.body)
        request = {"payload": payload,
                   "provider": PROVIDER_ID}
        request["policy_overrides"] = {
            "can_play": ast.literal_eval(os.environ["CAN_PLAY"]),
            "can_renew": ast.literal_eval(os.environ["CAN_RENEW"]),
            "license_duration_seconds": int(os.environ["LICENSE_DURATION_SECONDS"]),
            "renewal_delay_seconds": int(os.environ["RENEWAL_DELAY_SECONDS"]),
            "playback_duration_seconds": int(os.environ["PLAYBACK_DURATION_SECONDS"]),
            #"rental_duration_seconds": int(os.environ["RENTAL_DURATION_SECONDS"]),
            #"renewal_retry_interval_seconds": int(os.environ["RENEWAL_RETRY_INTERVAL_SECONDS"]),
            #"renewal_recovery_duration_seconds": int(os.environ["RENEWAL_RECOVERY_DURATION_SECONDS"])
        }
        if content_key_specs is None:
            request["allowed_track_types"] = os.environ["ALLOWED_TRACKS"]
        else:
            request["content_key_specs"] = content_key_specs

        if content_id:
            request["content_id"] = b64encode(unhexlify(content_id))

        _LOG.debug("License Request: {0}".format(json.dumps(request, indent=4)))
        return json.dumps(request)

    def retrieve_content_key_specs(self, content_id):
        _LOG.debug("Retrieving Content ID from KMS: {0}".format(content_id))
        if content_id in KMS:
            """Retrieve key_id y content_key from KMS given a content ID"""
            key_id, content_key = KMS[content_id]
            content_key_specs = [{"key": b64encode(unhexlify(content_key)),
                                  "key_id": b64encode(unhexlify(key_id)),
                                  "security_level": 1}]
        else:
            raise Exception("Content ID not found")

        return content_key_specs

    def build_parse_only_request(self):
        message = self.build_parse_only_message()
        request = b64encode(message)
        signature = self.generate_signature(message)
        license_info_request = json.dumps({"request": request,
                                           "signature": signature,
                                           "signer": PROVIDER_ID})
        return license_info_request

    def build_parse_only_message(self):
        """Build request with parse_only flag in order to retrieve the content ID"""
        payload = b64encode(self.request.body)
        request = {
            "payload": payload,
            "provider": PROVIDER_ID,
            "parse_only": True
        }
        _LOG.debug("Parse only Request: {0}".format(json.dumps(request, indent=4)))
        return json.dumps(request)

    def process_parse_only_response(self, response):
        session = {}
        response = json.loads(response)
        _LOG.debug("Parse only response: {0}".format(json.dumps(response, indent=4)))
        if response['status'] == "OK":
            if response['license_metadata']['request_type'] == "NEW":
                _LOG.debug("New license for session ID {0}".format(response['session_state']['license_id']['session_id']))
                if response['pssh_data']['content_id']:
                    content_id = hexlify(b64decode(response['pssh_data']['content_id']))
                    if len(sessions) == 0:
                        session_number = 1
                    else:
                        session_number = len(sessions) + 1
                    session['session_{0}'.format(session_number)] = {'content_id': content_id,
                                                                     'session_id': response['session_state']['license_id']['session_id']}
                sessions.append(session)
            elif response['license_metadata']['request_type'] == "RENEWAL":
                _LOG.debug("Renewing session's license {0}".format(response['session_state']['license_id']['session_id']))
                return
        else:
            raise Exception("Invalid license info with status: {0}".format(response['status']))
        return content_id

    def send_request(self, message_body):
        """Send HTTP request via urllib2"""
        try:
            f = urllib2.urlopen(LICENSE_SERVER_URL + "/" + PROVIDER_ID, message_body)
        except urllib2.HTTPError as e:
            raise Exception("Invalid license request with code {0} and reason '{1}'".format(e.code, e.reason))
        else:
            return f.read()

    def generate_signature(self, text_to_sign):
        """Ingest License Request and Encrypt"""
        hashed_text = hashlib.sha1(text_to_sign).digest()
        cipher = AES.new(PROVIDER_KEY, AES.MODE_CBC, PROVIDER_IV)
        padding = unhexlify("" if len(hashed_text) % 16 == 0 else (16 - (len(hashed_text) % 16)) * "00")
        aes_msg = cipher.encrypt(hashed_text + padding)
        signature = b64encode(aes_msg)
        return signature

    def process_license_response(self, response):
        """Decode License Response and pass to player"""
        license_response = json.loads(response)
        _LOG.debug("License response: {0}".format(json.dumps(license_response, indent=4)))
        _LOG.debug("Active sessions: {0}".format(sessions))
        if license_response["status"] == "OK":
            if license_response["message_type"] == "LICENSE" and "license" in license_response:
                license_decoded = b64decode(license_response["license"])
                return (True, license_decoded)
            else:
                raise Exception("Invalid license response: {0}".format(response))
        else:
            return(False, license_response["status"])

    def process_certificate_response(self, response):
        """Decode Certificate Response and pass to player"""
        certificate_response = json.loads(response)
        _LOG.debug("Certificate response: {0}".format(json.dumps(certificate_response, indent=4)))
        if certificate_response["status"] == "OK":
            if certificate_response["message_type"] == "SERVICE_CERTIFICATE" and "license" in certificate_response:
                certificated_decoded = b64decode(certificate_response["license"])
                return (True, certificated_decoded)
            else:
                raise Exception("Invalid certificate response: {0}".format(response))
        else:
            return(False, certificate_response["status"])

    def apply_bussiness_rules(self, content_id, token):
        if len(sessions) > int(os.environ['MAX_NUM_SESSIONS']):
            _LOG.debug("Denied busines rules: Too many devices")
            _LOG.debug("Playback not allowed for session ID: {0}".format(sessions[-1].values()[0]['session_id']))
            sessions.pop()
            return False
        else:
            _LOG.debug("Approved business rules")
            return True

    def get(self):
        """Handles HTTP Gets sent to the proxy."""
        self.debug_info = None
        self.send400("GET Not Supported")

    def send400(self, text):
        """Send 400 Error Response"""
        self.response.status = 400
        self.response.write(self.response.write(text))

    def send500(self, text):
        """Send 500 Error Response"""
        self.response.status = 500
        self.response.write(self.response.write(text))

app = webapp2.WSGIApplication([('/', proxyHandler), ], debug=True)


def main():

    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_certificate_chain_file("/root/localhost.crt")
    context.use_privatekey_file("/root/localhost.key")
    httpserver.serve(app, host="0.0.0.0", port="6060", ssl_context=context)

if __name__ == '__main__':
    main()
