# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

class IntegrationHelper:

    def __init__(self,
              username=None, password=None,
              certChain=None, privateKey=None,
              x509Fingerprint=None,
              settings = None):

        self.username = None
        self.password = None
        self.certChain = None
        self.privateKey = None
        self.checker = None

        #SRP Authentication
        if username and password and not \
                (certChain or privateKey):
            self.username = username
            self.password = password

        #Certificate Chain Authentication
        elif certChain and privateKey and not \
                (username or password):
            self.certChain = certChain
            self.privateKey = privateKey

        #No Authentication
        elif not password and not username and not \
                certChain and not privateKey:
            pass

        else:
            raise ValueError("Bad parameters")

        self.checker = Checker(x509Fingerprint)
        self.settings = settings