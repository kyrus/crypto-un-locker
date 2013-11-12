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
0x100      | remainder | File contents encrypted with above AES key

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
`bType` | 8 (`PLAINTEXTKEYBLOB`)
`bVersion` | 2
`reserved` | 0
`aiKeyAlg` | 0x6610 (`CALG_AES_256`)

## CryptoLocker Decrypter & Identification

Given the above file format, Kyrus has developed a CryptoLocker 
identification and decryption tool in Python. The tool can identify 
CryptoLocker files on a local disk and optionally decrypt them given the 
private key material.

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

