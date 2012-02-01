
try:
    import TACKpy # for accessing, say, SSL_Cert
    from TACKpy import TACK, TACK_Break_Sig
    tackpyLoaded = True
except ImportError:
    tackpyLoaded = False