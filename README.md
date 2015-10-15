# crypto-demo

First, a warning:

![img](http://i.imgur.com/YfFj3BG.png)
(via [moserware.com](http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html))

This software has been made by a single person in his spare time, to make a simple demo about how some cryptographical algorithms work.
This software's implementations of RSA, AES, AES-CBC and OAEP are as correct as my knowledge of the subject is, and do not try to be PKCS compliant, nor production ready.
Use them at your risk, without any warranty, and mostly DO NOT USE THIS FOR NOT DIDACTICAL PURPOSES!

Code is under Apache v2 license.

## Dependencies
- OpenSSL, for RNG, SHA512 and big integers. If you actually need crypto, use OpenSSL provided stuff, not this.

## What's in the demo:

A mostly working implementation of RSA with 4096 bit keys, an AES 256 implementation, a CBC encryption mode for AES and OAEP padding for RSA.

## Binaries:
*keygen*: generates RSA keys. May take a long time on Windows, expecially 32 bit.
*encr*: given a public key, it encrypts _stdin_ and outputs crypto data to stdout. RSA is used to encrypt a random generated AES key, which is used to encrypt hashes and text data in CBC mode and it's included with the cryptogram.
        See encrypt.h. The generated message is in the form E_PU(k) || E_k(msg), without taking into account hashes and length fields.
        
*decr*: given a private key, it decripts _stdin_ into _stdout_. 



