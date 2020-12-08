#!/usr/bin/python
from OpenSSL import crypto
import os
import sys
import datetime

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
now = datetime.datetime.now()
d = now.strftime("%H-%M-%S")

name = raw_input("give a name pls :)")
DIR = os.getcwd()
key = crypto.PKey()
keypath = DIR + name + '-' + str(d) + '.key'
csrpath = DIR + name + '-' + str(d) + '.csr'
crtpath = DIR + name + '-' + str(d) + '.crt'

def generatekey():

    if os.path.exists(keypath):
        print "Certificate file exists, aborting."
        print keypath
        sys.exit(1)
    else:
        print("Generating Key Please standby")
        key.generate_key(TYPE_RSA, 4096)
        f = open(keypath, "w")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        f.close()

generatekey()


def generatecsr():
    c = 'US'
    st = 'New York' #state
    l = 'New York City' #city
    o = 'New York University' #organization
    ou = 'Applied Crypto Project - Live Chat' #org unit
    req = crypto.X509Req()
    req.get_subject().CN = name
    req.get_subject().C = c
    req.get_subject().ST = st
    req.get_subject().L = l
    req.get_subject().O = o
    req.get_subject().OU = ou
    req.set_pubkey(key)
    req.sign(key, "sha512")

    if os.path.exists(csrpath):
        print "same path, abort"
        print csrpath
    else:
        f = open(csrpath, "w")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        f.close()
        print("key file created")


    cert = crypto.X509()
    cert.get_subject().CN = name
    cert.get_subject().C = c
    cert.get_subject().ST = st
    cert.get_subject().L = l
    cert.get_subject().O = o
    cert.get_subject().OU = ou
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha512")

    if os.path.exists(crtpath):
        print "same path, abort"  
        print crtpath
    else:
        f = open(crtpath, "w")
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        f.close()

generatecsr()

