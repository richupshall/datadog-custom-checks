import json
import urllib
import urllib2
import time

import subprocess
import sys


def lambda_handler(event, context):
    clients = [
        ["client1", [
            "client1.site.com",
            "www.client1.site2.com"]],
        ["client2", [
            "client2.anothersite.org"]]
    ]
    for client in clients:
        clientName = client[0]
        for domain in client[1]:
            sslExpiry(clientName, domain)
            sslProtocol(clientName, domain)
            sslAlgorithm(clientName, domain)
            sslCipher(clientName, domain)

    return "complete"


def logMetric(metric,  value, tags=None):
    print("MONITORING|" + str(int(time.time())) + "|" + str(value) + "|gauge|" + metric + "|#" + tags)


def sslExpiry(clientName, domain, port='443'):
    p = subprocess.Popen("echo | openssl s_client -connect " + domain + ":" + port +
                         " 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -f 2 -d\= | xargs -0 -I arg date -d arg \"+%s\"", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    if output:
        output = output.rstrip("\n")
        d0 = int(time.time())
        d1 = int(output)
        delta = d1 - d0
        days = delta / 24 / 60 / 60  # convert the timestamp to days
    else:
        days = -1
        d0 = int(time.time())

    tag = "site:" + domain + ",client:" + clientName
    logMetric('ssl.expire_in_days', days, tags=tag)


def sslProtocol(clientName, domain, protocol='ssl3', port='443'):
    p = subprocess.Popen("echo QUIT | openssl s_client -connect " + domain + ":" + port + " -" +
                         protocol + " 2>/dev/null | grep \"BEGIN CERTIFICATE\"", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    if output:
        output = output.rstrip("\n")
        protocolEnabled = 1
        protocolText = 'enabled'
    else:
        protocolEnabled = 0
        protocolText = 'not enabled'

    tag = "site:" + domain + ",client:" + clientName
    logMetric('ssl.protocol_enabled.' + protocol,
                protocolEnabled, tags=tag)


def sslCipher(clientName, domain, cipher='RC4', port='443'):
    p = subprocess.Popen("echo QUIT | openssl s_client -connect " + domain + ":" + port + " -cipher " +
                         cipher + " 2>/dev/null | grep \"BEGIN CERTIFICATE\"", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    if output:
        output = output.rstrip("\n")
        cipherEnabled = 1
        cipherText = 'enabled'
    else:
        cipherEnabled = 0
        cipherText = 'not enabled'

    tag = "site:" + domain + ",client:" + clientName
    logMetric('ssl.cipher_enabled.' + cipher,
                cipherEnabled, tags=tag)


def sslAlgorithm(clientName, domain, port='443'):
    p = subprocess.Popen("echo QUIT | openssl s_client -connect " + domain + ":" + port +
                         " 2>/dev/null | sed -ne '/---BEGIN/,/---END/p' | openssl x509 -text -noout | grep 'Signature Algorithm: ' | head -1 | sed -e 's/^[ \t]*//' | cut -d' ' -f3", stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    if output:
        algorithm = output.rstrip("\n")
        if algorithm == 'sha256WithRSAEncryption':
            SHAversion = 2
        elif algorithm == 'sha1WithRSAEncryption':
            SHAversion = 1
        else:
            SHAversion = 0
    else:
        SHAversion = 0

    tag = "site:" + domain + ",client:" + clientName
    logMetric('ssl.sha.version', SHAversion, tags=tag)


