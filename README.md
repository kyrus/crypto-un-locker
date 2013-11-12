# CryptoLocker Encrypted File Format

Each file encrypted by CryptoLocker is encrypted with a unique AES-256 
key. The unique symmetric key is then encrypted with the public RSA-2048 
key unique to the infected host. Therefore, the only way to decrypt 
files encrypted with CryptoLocker is to obtain the private RSA-2048 key.

The file format for an encrypted file is as follows:

Offset     | Length | Description
---------- | ------ | -----------
0x00       | 0x14   | SHA1 hash of '\x00'\*4 followed by the next 0x100 bytes (the "file header")
0x14       | 0x100  | File header containing the AES key encrypted with RSA-2048 with PKCS#1 v1.5 padding
0x114      | remainder | File contents encrypted with above AES key

Once the file header is decrypted, The `CryptImportKey` Win32 CryptoAPI 
function is used to interpret a Microsoft 
[`PUBLICKEYSTRUC`](http://msdn.microsoft.com/en-us/library/windows/desktop/aa387453%28v=3Dvs.85%29.aspx) 
structure. The format of the `PUBLICKEYSTRUC` structure is:

	typedef struct _PUBLICKEYSTRUC {
	  BYTE   bType;
	  BYTE   bVersion;
	  WORD   reserved;
	  ALG_ID aiKeyAlg;
	} BLOBHEADER, PUBLICKEYSTRUC;

For CryptoLocker, the following values are used:

Field | Value
----- | -----
`bType` | 0x08 (`PLAINTEXTKEYBLOB`)
`bVersion` | 0x02
`reserved` | 0x0000
`aiKeyAlg` | 0x6610 (`CALG_AES_256`)

## CryptoLocker Decrypter & Identification

Given the above file format, Kyrus has developed a CryptoLocker 
identification and decryption tool in Python. The tool can identify 
CryptoLocker files on a local disk and optionally decrypt them given the 
private key material.

CryptoUnLocker requires Python 2.7 and the [PyCrypto](https://pypi.python.org/pypi/pycrypto)
module.

## Usage

	usage: CryptoUnLocker.py [-h] (--keyfile KEYFILE | --keydir KEYDIR) [-r] [-v]
	                         [--dry-run] [--detect]
	                         encrypted_filenames [encrypted_filenames ...]

	Decrypt CryptoLocker encrypted files.

	positional arguments:
	  encrypted_filenames

	optional arguments:
	  -h, --help           show this help message and exit
	  --keyfile KEYFILE    File containing the private key, or the EXE file
	                       provided for decryption
	  --keydir KEYDIR      Directory containing any number of private keys; the
	                       appropriate private key will be used during the
	                       decryption process
	  -r                   Recursively search subdirectories
	  -v                   Verbose output
	  --dry-run            Don't actually write decrypted files
	  --detect             Don't try to decrypt; just find files that may be
	                       CryptoLockered
	  -o DESTDIR           Copy all decrypted files to an output directory,
	                       mirroring the source path

By default, if CryptoUnLocker is able to decrypt a file, it will overwrite the 
original file with the decrypted version and copy the original encrypted
version to the filename + `.bak` extension.

The optional `-o` argument causes CryptoUnLocker to mirror the original source
directory structure, copying decrypted files into the destination directory
specified by `-o`. For example, given the following command line:

	CryptoUnLocker.py --keydir /keys -o /mnt/output -r /mnt/input

will find all files in /mnt/input, and any that are CryptoLockered will be 
decrypted to the same directory and filename under /mnt/output.

