#!/usr/bin/env python

import struct
import os
import argparse
import shutil
import sys
from collections import namedtuple
from datetime import datetime
import csv
import re

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Util.number import bytes_to_long


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

PUBLICKEYSTRUC = namedtuple('PUBLICKEYSTRUC', 'bType bVersion reserved aiKeyAlg')
RSAPUBKEY = namedtuple('RSAPUBKEY', 'magic bitlen pubexp')
PRIVATEKEYBLOB = namedtuple('PRIVATEKEYBLOB', 'modulus prime1 prime2 exponent1 exponent2 coefficient privateExponent')

PUBLICKEYSTRUC_s = struct.Struct('<bbHI')
RSAPUBKEY_s = struct.Struct('<4sII')

key_re = re.compile('-----BEGIN.*KEY-----\n(.*)\n-----END.*KEY-----', re.DOTALL)


def subtract(a,b):
    if a == None or b == None:
        return None
    else:
        return ord(b)-ord(a)

class OutputLevel:
    VerboseLevel, InfoLevel, WarnLevel, ErrorLevel = range(4)

class CryptoUnLocker(object):
    def __init__(self):
        self.keys = []

    def loadKeyFromFile(self, fn):
        d = open(fn, 'rb').read()

        matches = key_re.match(d)
        if matches:
            self.loadKeyFromString(matches.group(0))
            return

        # fall through if the file does not contain a PEM encoded RSA key
        # try the CryptImportKey Win32 file format
        if self.CryptImportKey(d):
            return

        # Apparently a new version of CryptoLocker is adding what looks
        # like a version number to the start of the RSA key format. Try
        # skipping over the first four bytes of the file then interpreting
        # the rest as an RSA private key.
        if self.CryptImportKey(d[4:]):
            return

        # if we can't import the file, raise an exception
        raise Exception("Could not parse a private key from file")

    def CryptImportKey(self, d):
        publickeystruc = PUBLICKEYSTRUC._make(PUBLICKEYSTRUC_s.unpack_from(d))
        if publickeystruc.bType == 7 and publickeystruc.bVersion == 2 and publickeystruc.aiKeyAlg == 41984:
            rsapubkey = RSAPUBKEY._make(RSAPUBKEY_s.unpack_from(d[8:]))
            if rsapubkey.magic == 'RSA2':
                bitlen8 = rsapubkey.bitlen/8
                bitlen16 = rsapubkey.bitlen/16
                PRIVATEKEYBLOB_s = struct.Struct('%ds%ds%ds%ds%ds%ds%ds' % (bitlen8, bitlen16, bitlen16, bitlen16, bitlen16, bitlen16, bitlen8))
                privatekey = PRIVATEKEYBLOB._make(map(bytes_to_long, PRIVATEKEYBLOB_s.unpack_from(d[20:])))

                r = RSA.construct((privatekey.modulus, long(rsapubkey.pubexp), privatekey.privateExponent, 
                    privatekey.prime1, privatekey.prime2))
                self.keys.append(r)
                return True

        return False

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

    def guessIfWiped(self, fn):
        file_header = open(fn, 'rb').read(64)
        if len(file_header) != 64:
            return False

        lst = map(subtract, file_header[:32:2], file_header[1:32:2])
        return not lst or [lst[0]]*len(lst) == lst

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

class CryptoUnLockerProcess(object):
    def __init__(self, args, unlocker):
        self.args = args
        self.unlocker = unlocker
        self.csvfp = None
        self.csv = None

    def doit(self):
        if self.args.csvfile:
            self.csvfp = open(self.args.csvfile,'wb')
            self.csv = csv.writer(self.csvfp)
            self.csv.writerow(['Timestamp', 'Filename', 'Message'])

        keyfiles = []
        if self.args.keyfile:
            keyfiles = [self.args.keyfile]
        elif self.args.keydir:
            keyfiles = [os.path.join(self.args.keydir, fn) for fn in os.listdir(self.args.keydir)]

        for fn in keyfiles:
            try:
                self.unlocker.loadKeyFromFile(fn)
                self.output(OutputLevel.VerboseLevel, fn, "Successfully loaded key file")
            except Exception, e:
                self.output(OutputLevel.ErrorLevel, fn, "Unsuccessful loading key file: %s" % e.message)

        if not len(self.unlocker.keys) and not self.args.detect:
            self.output(OutputLevel.ErrorLevel, '', 'No key files were successfully loaded. Exiting.')
            return 1

        if self.args.recursive:
            for root, dirs, files in os.walk(self.args.encrypted_filenames[0]):
                for fn in files:
                    self.processFile(root, fn)
        else:
            for fn in self.args.encrypted_filenames:
                self.processFile('', fn)

        return 0

    def processFile(self, pathname, fn):
        if fn.endswith('.bak'):
            # skip backup files
            return

        fullpath = os.path.join(pathname, fn)

        try:
            if self.unlocker.guessIfWiped(fullpath):
                self.output(OutputLevel.VerboseLevel, fullpath, "File appears wiped")
                return
            elif not self.unlocker.isCryptoLocker(fullpath):
                self.output(OutputLevel.VerboseLevel, fullpath, "Not a CryptoLocker file")
                return
            else:
                if self.args.detect:
                    self.output(OutputLevel.InfoLevel, fullpath, "Potential CryptoLocker file")
                    return
        except Exception, e:
            self.output(OutputLevel.ErrorLevel, fullpath, "Unsuccessful opening file: %s" % e.message)
            return

        try:
            decrypted_file = self.unlocker.decryptFile(fullpath)
            self.output(OutputLevel.InfoLevel, fullpath, "Successfully decrypted file")
            if not self.args.dry_run:
                if self.args.destdir:
                    destdir = os.path.join(self.args.destdir, pathname)
                    if not os.path.exists(destdir):
                        os.makedirs(destdir)
                    open(os.path.join(destdir, fn), 'wb').write(decrypted_file)
                else:
                    shutil.copy2(fullpath, fullpath + ".bak")
                    open(os.path.join(pathname, fn), 'wb').write(decrypted_file)
        except Exception, e:
            self.output(OutputLevel.ErrorLevel, fullpath, "Unsuccessful decrypting file: %s" % e.message)

    def output(self, level, fn, msg):
        if level == OutputLevel.VerboseLevel and not self.args.verbose:
            return

        if self.csv:
            self.csv.writerow([datetime.now(), fn, msg])

        icon = '[.]'
        if level == OutputLevel.InfoLevel:
            icon = '[+]'
        elif level > OutputLevel.InfoLevel:
            icon = '[-]'

        if fn:
            sys.stderr.write('%s %s: %s\n' % (icon, msg, fn))
        else:
            sys.stderr.write('%s %s\n' % (icon, msg))
        sys.stderr.flush()

def main():
    parser = argparse.ArgumentParser(description='Decrypt CryptoLocker encrypted files.')
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('--keyfile', action='store', dest='keyfile',
                        help='File containing the private key, or the EXE file provided for decryption')
    group.add_argument('--keydir', action='store', dest='keydir',
                        help='Directory containing any number of private keys; the appropriate private key will be used during the decryption process')
    group.add_argument('--detect', action='store_true', dest='detect', help="Don't try to decrypt; just find files that may be CryptoLockered")

    parser.add_argument('-r', action='store_true', dest='recursive', help="Recursively search subdirectories")
    parser.add_argument('-v', action='store_true', dest='verbose', help="Verbose output")
    parser.add_argument('--dry-run', action='store_true', dest='dry_run', help="Don't actually write decrypted files")
    parser.add_argument('-o', action='store', dest='destdir', help='Copy all decrypted files to an output directory, mirroring the source path')
    parser.add_argument('--csv', action='store', dest='csvfile', help='Output to a CSV file')

    parser.add_argument('encrypted_filenames', nargs="+")

    results = parser.parse_args()
    unlocker = CryptoUnLocker()
    processor = CryptoUnLockerProcess(results, unlocker)

    return processor.doit()

if __name__ == '__main__':
    sys.exit(main())

