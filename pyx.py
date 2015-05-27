#!/usr/bin/env python

import subprocess
import sys

# decode x509 certificate
def decodeCert(cert):
    x509_output = subprocess.Popen(
    ['openssl', 'x509', '-text', '-noout', '-in', cert], 
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # store subprocess command output in 'cert_array'
    cert_array, err = x509_output.communicate()

    # return output value
    return cert_array

# decode certificate signing request
def decodeCSR(cert):
    x509_output = subprocess.Popen(
    ['openssl', 'req', '-text', '-noout', '-in', cert], 
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # store subprocess command output in 'cert_array'
    csr_array, err = x509_output.communicate()

    # return output value
    return csr_array


# decode rsa private key
def decodeRSAkey(cert):
    x509_output = subprocess.Popen(
    ['openssl', 'rsa', '-text', '-noout', '-in', cert], 
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # store subprocess command output in 'cert_array'
    rsa_array, err = x509_output.communicate()

    # return output value
    return rsa_array

def main():
    # Map input argument to variable 'cert'
    cert_file=str(sys.argv[1])

    # Call our command!
    #out = decodeCert(cert_file)
    out = decodeCSR(cert_file)
    #out = decodeRSAkey(cert_file)

    print out

if __name__ == '__main__':
    main()
