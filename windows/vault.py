#!/usr/bin/env python

""" Perform initial vault login using k8s SA token in order to generate a client token """

__author__ = 'Moshe Shitrit'
__creation_date__ = '9/12/18'

import os
import json
import requests
import sys
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import commonutil
import socket
import logging
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

print """
 ___ ___                __  __        _______         __                       _______                                    __
|   |   |.---.-..--.--.|  ||  |_     |_     _|.-----.|  |--..-----..-----.    |     __|.-----..-----..-----..----..---.-.|  |_ .-----..----.
|   |   ||  _  ||  |  ||  ||   _|      |   |  |  _  ||    < |  -__||     |    |    |  ||  -__||     ||  -__||   _||  _  ||   _||  _  ||   _|
 \_____/ |___._||_____||__||____|      |___|  |_____||__|__||_____||__|__|    |_______||_____||__|__||_____||__|  |___._||____||_____||__|


"""

root = commonutil.get_logger()

expected_vars = ['VAULT_ADDR', 'VAULT_ROLE', 'VAULT_K8S_MOUNT_PATH']
commonutil.verify_expected_vars(expected_vars)

VAULT_ADDR = os.getenv('VAULT_ADDR')

logging.debug('Started debuging hostname resolution for vault url')
VAULT_URL=commonutil.hostname_resolution(VAULT_ADDR)
vault_certs_path = "/usr/local/certs/cer.crt"

print(VAULT_URL)

# ================== END GLOBAL ================== #

def get_vault_token():
    """
    Initiate the Vault login flow using provided environment variables
    :return: void
    """
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as sa_token:
        data = {
            "jwt": sa_token.readline().rstrip(),
            "role": os.getenv("VAULT_ROLE")
        }
    root.debug(msg="Payload: {}".format(data))
    url = "{0}/v1/auth/{1}/login".format((VAULT_URL), os.getenv('VAULT_K8S_MOUNT_PATH'))
    root.debug(msg="URL: {}".format(url))

    session = commonutil.retry_session(retries=5)
    data_content = json.dumps(data)
    response = session.post(url=url, data=json.dumps(data), headers={}, verify=vault_certs_path)
    if response.status_code != 200:
        root.critical(msg="Vault login failed with error {0} ({1}, {2})".format(response.status_code,
                                                                                response.reason,
                                                                                response.text.rstrip()))
    else:
        root.info(msg="Vault login succeeded")
        vault_token = json.loads(response.text)['auth']['client_token']
        with open('/var/secret/vault_access_token', 'w') as tf:
            tf.write(vault_token)
        os.environ["VAULT_TOKEN"] = vault_token

def get_vault_data(url, token, path):
    '''
    Retrieves data elements from vault
    '''
    result = None
    if url and token and path:
        try:
            r = requests.get(url + '/v1/' + path, verify=vault_certs_path, headers={'X-Vault-Token':token})
            print r
            if r.status_code == 200:
                result = r.json()['data']
                root.info(msg="Secrets will be written to /var/secret/setvars")
            else:
                raise Exception("Status %s from vault" % r.status_code)
        except Exception as ex:
            raise Exception("Exception retrieving vault data for %s:%s: %s" % (token, path, ex))
    else:
        raise Exception("Vault token or path missing")
    return result

def main():
    get_vault_token()
    VAULT_CONF_PATH = os.environ.get('SECRET_PATH')
    VAULT_TOKEN = os.environ.get('VAULT_TOKEN')
    if VAULT_CONF_PATH:
        list = VAULT_CONF_PATH.split (",")
        with open('/var/secret/setvars', 'w') as fd:
            for i in list:
                data = get_vault_data(VAULT_ADDR, VAULT_TOKEN, i.strip())
                for key in data:
                    fd.write('set ' + ''+ str(key) +'' + '=' + ''+ str(data[key]).replace("&","^&") +'' + '\n')
                                    
if __name__ == '__main__':
    main()

