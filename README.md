One-time pad on steroids
=========================

Features
---------

Crypt0 provides the following features:

* implementation of the **one-time pad cipher**;
* **message integrity** protection with SHA512 HMAC, not provided by naive implementations of the one-time pad;
* **additional layer of 256 bits AES** that hardens cryptanalisys in case of two-time pad or flawed RNG;
* helpers for pads management;
* some **metadata protection**, ciphertext looks like a fixed-size random bulk of data;
* short, clear and portable source code written in Go (a buffer-overflow safe, strongly typed, fast and compiled language);
* everything is inside the binary, no dependencies.

Assumptions
------------

Crypt0 securely works only if the following assumptions are true.

* Any environment that "can see" plaintext data or pads is safe (no possible unauthorized access to data, no malwares, no backdoors, no TEMPEST...).
* Pads are transported and exchanged in a way that is safe from alterations or leaks (see the first assumption).
* Pads are generated with a safe TRNG. Safe PRNGs should work well and provide a good level of security but will not reach the mathematical unbreakability.
* HMAC-SHA512 (with unique random keys) is secure. In case it would not be, only the integrity might be altered with a very low probability. Confidentiality doesn't depend on HMAC-SHA512 and remains unquestioned.
* AES with CFB operation mode with random IVs is secure. In case it would not be, confidentiality could be broken only if the pad is not random or not unique.

Changelog
----------

Versions of crypt0 are composed of 3 numbers X.Y.Z.

X is increased when major changes that can break retro-compatibility happen.

Y is increased when new features are added.

Z is increased when for minor changes such as bug fixes or code clean-ups.

* 0.3.1
  * Improvement of the GUI wrapper for encryption
* 0.3.0
  * Minor changes to GUI wrappers
  * Refactored .desktop files
* 0.2.0
  * Added genpads0
  * Various code clean-ups
* 0.1.0
  * GUI integration:
    * Fixed some bugs
    * Added peer (and $CRYPT0_HOME) support
* 0.0.0
  * Initial release

License
--------

All the work related to crypt0 is Copyright 2015, Piotr Chmielnicki. The code is under GNU GPL version 3.

User guide
===========

Crypt0 is a set of tools:

* `encrypt0`: the command-line command for encryption
* `encrypt0-gui`: the GUI wrapper for `encrypt0` (Linux and BSD only)
* `decrypt0`: the command-line command for decryption
* `decrypt0-gui`: the GUI wrapper for `decrypt0` (Linux and BSD only)
* `.desktop` files for gui wrappers
* `genpads0` our command line tool for pad generation

Usages
--------

### encrypt0

    Usage:
    
    encrypt0 [--short] plaintext-file pad
    
    plaintext-file: the file to encrypt
    pad           : the pad to use (a .w.pad file)
    --short       : do not add padding to the plaintext, the ciphertext will be shorter but will leak the file size
    
    Return values:
    
    0: encryption success
    1: pad is too short
    9: other error

### decrypt0

    Usage:
    
    decrypt0 ciphertext-file pad
    
    ciphertext-file: the file to decrypt (a .enc file)
    pad            : the pad (a .r.pad file) to use or a directory containing it
    
    Return values:
    
    0: decryption success
    1: invalid pad or no valid pad in the directory
    9: other error

### genpads0

    Usage:
    
    form 1: genpads0 size pad-name
    form 2: genpads0 size number peer1 peer2
    form 3: genpads0 size number peers-file
    
    size      : size of a pad in kio (1 kio = 1024 bytes)
    pad-name  : file name of the pad to generate
    number    : number of pads to generate per communication way
    peer1|2   : peer's name (Such as "Alice" or "Bob"
    peers-file: a CSV file containing communication channel between peers
                each line is of the following form SENDER,RECIPIENT1[,RECIPIENT2[...]]
    
    Environment:
    
    CSTRNG: cryptographically secure true random number generator. Readable file expected (multiple files can be supplied separated by ':')
    PRNG  : pseudo-random number generator. Readable file expected (multiple files can be supplied separated by ':')
    
    Return values:
    
    0: success
    9: error

This tool stores pads in folders, here is an example of folders layout for communication between Alice and Bob:

    alice.pads # This folder should be given to Alice
    `-- bob    # Communication with Bob (from Alice's point of vue)
        |-- 13c1a6f19d829790.w.pad 
        `-- 13c1a6f19eb301fe.r.pad 
    bob.pads   # This folder should be given to Bob
    `-- alice  # Communication with Alice (from Bob's point of vue)
        |-- 13c1a6f19d829790.r.pad 
        `-- 13c1a6f19eb301fe.w.pad 

GUI scripts
------------

`encrypt0-gui` and `decrypt0-gui` are two Linux (bash) scripts taking as optional argument the name of an input file.
These scripts allow to graphically select a pad or a “peer”.
A peer is a person your are communicating with.
Peers can be added by adding a directory in $CRYPT0_HOME/peers/.
This peer will take the name of the directory and all pads located in the directory might be used to communicate with the peer.

By default, CRYPT0_HOME=~/.crypt0

Here is an example of a CRYPT0_HOME tree:

    .crypt0/ 
    `-- peers 
        |-- John\ Doe # A friend 
        |   |-- 13c1a6a1a8f01e15.w.pad # A pad to write to John
        |   `-- 13c1a6a1a7b780fa.r.pad 
        `-- Trinity # An other one
            |-- 13c1a6a1a9d845d6.r.pad # A pad to read from Trinity
            `-- 13c1a6a1aa3c35cb.w.pad

Internals
==========

First, let's define some terms.

* _AES_(x, y, z): the encryption with AES cipher in CFB mode of the message z with the 256 bits key x and the IV y.
* _HMAC_(x, y):  the HMAC of y with SHA512 hash algorithm and 768 bits key x.
* _XOR_(x, y): xor between the bit streams x and y. 
* _AES_K_: the 256 bits key of the _AES_ cipher.
* _IV_: the 128 bits IV of the _AES_ cipher.
* _HMAC_K_:the 768 bits of the _HMAC_.
* _XOR_K_: the key stream for one-time pad _XOR_.

The first byte of a sequence is the byte number 0.

How the pad is used
--------------------

* Bytes from 0 to 95 are used as _HMAC_K_.
* Bytes from 96 to 127 are used as _AES_K_.
* Bytes from 128 the end of the file are used as _XOR_K_

Ciphertext format
------------------

During encryption the plaintext passes 3 encoding steps:

### Encoding step 1 : header and padding

The result of the first encoding step is composed of the following concatenated elements:

1. 0x00 8 bytes header;
2. big endian encoded 64 bits size of the plaintext (8 bytes);
3. the plaintext;
4. 0x00 padding of undefined size (used to mask the plaintext size).

### Encoding step 2 : one-time pad encryption

The result of the second encoding step is _XOR_(step 1 result, _XOR_K_).

### Encoding step 3: AES and HMAC

The result of the third encoding step is composed of the following concatenated elements:

1. _IV_;
2. _AES_(_AES_K_, _IV_, step 2 result);
3. _HMAC_(_HMAC_K_, 2 previous elements).

Pad generation (genpads0)
--------------------------

The genpads0 tool mixes various sources of entropy:

* the secure pseudo-random number generator provided by the operating system;
* optional other sources pointed by environment variables (see usage).

All streams are xored together.
48 bytes of the resulting stream are used to initialize an AES 256 bits cipher in CTR mode that will encrypt the rest of the resulting stream before it gets written to new pads.
This encryption can be regarded as entropy post-treatment.

Building crypt0
================

You will need a Go compiler.
The reference compiler will always be the latest stable release of the official Go compiler.
On Linux a makefile is available, `make all` will compile the project and `make install` will install it for an unprivileged user.
Other options are available. The makefile is easy to read.

