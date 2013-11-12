#!/usr/bin/env python

import struct
import os
import argparse
import glob
import shutil

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA


"""
CryptoLocker file structure:

0x14  bytes : SHA1 hash of '\x00'*4 + next 0x100 bytes of file.
0x100 bytes : AES key encrypted with RSA PKCS#1 v1.5:
 0x2c bytes :  AES key blob

remainder   : file data encrypted with AES256-CBC with IV of 0x00

Key blob is a Microsoft PUBLICKEYSTRUC:
typedef struct _PUBLICKEYSTRUC {
  BYTE   bType;
  BYTE   bVersion;
  WORD   reserved;
  ALG_ID aiKeyAlg;
} BLOBHEADER, PUBLICKEYSTRUC;

where:
bType    = 0x08
bVersion = 0x02
reserved = 0
aiKeyAlg = 0x6610 (AES-256)

followed by a DWORD length of 0x20, and finally the 32 byte AES key.
"""


class CryptoUnLocker(object):
    def __init__(self):
        self.keys = []

    def loadKeyFromFile(self, fn):
        d = open(fn, 'rb').read()

        startpos = d.find('-----BEGIN PRIVATE KEY-----')
        endpos = d.find('-----END PRIVATE KEY-----')

        if startpos == -1 or endpos == -1:
            raise Exception("Could not parse a private key from file %s" % fn)

        d = d[startpos:endpos+len('-----END PRIVATE KEY-----')]

        self.loadKeyFromString(d)

    def loadKeyFromString(self, s):
        r = RSA.importKey(s)
        self.keys.append(r)

    def isCryptoLocker(self, fn):
        file_header = open(fn, 'rb').read(0x114)
        if len(file_header) != 0x114:
            return False

        # validate that the header is correct
        header_hash = SHA.new('\x00'*4 + file_header[0x14:0x114])
        return header_hash.digest() == file_header[:0x14]

    def decryptFile(self, fn):
        aes_key = None

        with open(fn, 'rb') as fp:
            file_header = fp.read(0x114)

            if len(file_header) != 0x114:
                raise Exception("Not a CryptoLocker file")

            for rsa_key in self.keys:
                aes_key = self.retrieveAESKey(rsa_key, file_header)
                if aes_key:
                    break

            if not aes_key:
                raise Exception("Could not find the private key for this CryptoLocker file")

            # read the remaining data and decrypt with the AES key
            d = fp.read()
            a = AES.new(aes_key, mode=AES.MODE_CBC, IV='\x00'*16)
            d = a.decrypt(d)
            d = d[:-ord(d[-1])]

            return d

    def retrieveAESKey(self, r, file_header):
        # we have to reverse the bytes in the header to conform with the CryptoAPI
        # CryptDecrypt function.
        file_header = file_header[0x14:0x114]
        file_header = file_header[::-1]

        # decrypt the AES key blob
        c = PKCS1_v1_5.new(r)
        sentinel = '\x00' * 16
        blob = c.decrypt(file_header, sentinel)

        # retrieve key from file_header
        (bType, bVersion, reserved, aiKeyAlg, keyLen) = struct.unpack('<BBHII', blob[:0xc])
        if bType == 0x08 and bVersion == 0x02 and reserved == 0 and \
            aiKeyAlg == 0x6610 and keyLen == 32:
            aes_key = blob[0x0c:0x0c+32]
            return aes_key
        else:
            return None

def processFile(unlocker, args, pathname, fn):
    if fn.endswith('.bak'):
        # skip backup files
        return

    fullpath = os.path.join(pathname, fn)

    try:
        isCryptoLocker = unlocker.isCryptoLocker(fullpath)
        if not isCryptoLocker:
            if args.verbose:
                print '[.] Not a CryptoLocker file:', fullpath
            return
        else:
            if args.detect:
                print '[+] Found a potential CryptoLocker file:', fullpath
                return
    except Exception, e:
        print '[-] ERROR opening file %s: %s' % (fullpath, e.message)

    try:
        decrypted_file = unlocker.decryptFile(fullpath)
        print '[+] Successfully decrypted file', fn
        if not args.dry_run:
            if args.destdir:
                destdir = os.path.join(args.destdir, pathname)
                if not os.path.exists(destdir):
                    os.makedirs(destdir)
                open(os.path.join(destdir, fn), 'wb').write(decrypted_file)
            else:
                shutil.copy2(fn, fn + ".bak")
                open(os.path.join(pathname, fn), 'wb').write(decrypted_file)
    except Exception, e:
        print '[-] UNSUCCESSFUL decrypting file %s: %s' % (fn, e.message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt CryptoLocker encrypted files.')
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('--keyfile', action='store', dest='keyfile',
                        help='File containing the private key, or the EXE file provided for decryption')
    group.add_argument('--keydir', action='store', dest='keydir',
                        help='Directory containing any number of private keys; the appropriate private key will be used during the decryption process')

    parser.add_argument('-r', action='store_true', dest='recursive', help="Recursively search subdirectories")
    parser.add_argument('-v', action='store_true', dest='verbose', help="Verbose output")
    parser.add_argument('--dry-run', action='store_true', dest='dry_run', help="Don't actually write decrypted files")
    parser.add_argument('--detect', action='store_true', dest='detect', help="Don't try to decrypt; just find files that may be CryptoLockered")
    parser.add_argument('-o', action='store', dest='destdir', help='Copy all decrypted files to an output directory, mirroring the source path')

    parser.add_argument('encrypted_filenames', nargs="+")

    results = parser.parse_args()

    unlocker = CryptoUnLocker()

    if results.keyfile:
        unlocker.loadKeyFromFile(results.keyfile)
    elif results.keydir:
        for fn in os.listdir(results.keydir):
            try:
                unlocker.loadKeyFromFile(os.path.join(results.keydir, fn))
                if results.verbose:
                    print '[+] Successfully loaded key file', fn
            except Exception, e:
                print '[-] Could not load key file %s: %s' % (fn, e.message)

    if results.recursive:
        for root, dirs, files in os.walk(results.encrypted_filenames[0]):
            for fn in files:
                processFile(unlocker, results, root, fn)
    else:
        for g in results.encrypted_filenames:
            for fn in glob.glob(g):
                processFile(unlocker, results, '', fn)
