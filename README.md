# CloudCrypto
A library for cryptographic primitive implementations for Cloud Storage / Computing applications.

## Overview

While traditional public key cryptographic primitives (e.g., RSA, ElGamals) have been applied in practice, 
many advanced cryptographic primitives and schemes are further proposed or will be proposed 
that may have potential usage in future Cloud Storage/Computing applications. 
These schemes can be classified into two categoaries.

- Cloud Storage: for fine-grained access control, i.e., Predicate Encryption based on Bilinear Groups;
- Cloud Computing: for data process delegation, i.e., Fully Homomorphic Encryption based on (Ideal) Lattices;

This project aims at implementing such schemes under the well-known Bouncy Castle Java Cryptography Environment architecture. 
Although Java seems not a good choice for Crypto implementations due to runtime effiency, 
we choose it since Java provides good portability so that the codes can be even **directly** port to mobile devices for usages.

**Warning: The current library cannot be directly used in practice. It is mainly for academic researches.**

### Cryptographic Primitives for Cloud Storage

We are now mainly focus on implementing Predicate Encryption schemes based on Bilinear Groups. 
The underlying algebric library is [Java Pairing-Based Cryptography Library](http://gas.dia.unisa.it/projects/jpbc/).
Note that there are some schemes implementations in Java Pairing-Based Cryptography, but with the following issues:

- There is no avaiable serialization methods.
- The implementations indeed encrypt a random element in G_T. 
But the APIs do not provide a method to get this element for further encryption.

In our implementations, we overcome the above issues:

- We provide a serialization method, which allows serializing CipherParameters (Master Secret Key, Secret Key, and **Ciphertext**) into XML files.
This allows users to actually generate a ciphertext for further uploading to public Clouds.
- We provide a key encapsulation mechanism for these schemes, i.e., the encryption scheme encapsulates a random session key,
by which the encryptor can use to encrypt arbitrary data.

### Cryptographic Primitives for Cloud Computing

For Fully Homomorphic Encryption based on (Ideal) Lattices, we are busy finding reliable underlying algebric library. 
We strongly welcome you to provide us useful suggestions and methods for implementing even Lattice-Based Cryptography in Java.

## Develope Environments

Similar to Java Pairing-Based Cryptography Library, 
CloudCrypto is built using Maven 2. You can download it from [http://maven.apache.org](http://maven.apache.org).

There are a few dependencies which are hosted on any publicly available Maven Repository 
so Maven will be able to resolve them automatically.
The only Jar library that you may need to download and configure by yourself is JPBC itself. 

The development enviroment is IntelliJ IDEA. In fact, the source codes is a whole IDEA project.
For the ones who want to have a try, please simply download the code and import it into IntelliJ IDEA.

## Schemes

We have implemented the following schemes. We will continue implementing others.

### Revocation Systems

- Lewko-Sahai-Waters Simple Revocation Systems (Security and Privacy 2010).
- Chosen ciphertext secure Online/Offline LSW simple Revocation Systems 
based on the transformation technique proposed by me, Prof. Jianwei Liu, Prof. Qianhong Wu, and Dr. Bo Qin.
(**The corresponding paper has been submitted to ESORICS 2016, under review**).

### Identity-Based Encryption

- (2016.05.07) Lewko-Waters Identity-Based Encryption scheme (TCC 2010).

### Hierarhical Identity-Based Encryption

- Boneh-Boyen Hierarchical Identity-Based Encryption scheme (EUROCRYPT 2004).
- Boneh-Boyen-Goh Hierarhical Identity-Based Encryption scheme (EUROCRYPT 2005).

### Chameleon Hash Functions
Since the Online/Offline Predicate Encryption transformation technique 
proposed by me, Prof. Jianwei Liu, Prof. Qianhong Wu, and Dr. Bo Qin 
uses Chameleon hash as the underlying primitives, we implement some well-known Chameleon hash functions on group G_T 
for constructing instantiations of our transformation. The schemes include:

- Katz-Rabin Chameleon Hash (NDSS 2000).
- Chen-Zhang-Kim Chameleon Hash without Key Exposure (ISC 2004).

## Contact and Contribute

### Contact 

CloudCrypto is mainly developed by Weiran Liu.

Feel free to contact me at [liuweiran900217@gmail.com](mailto:liuweiran900217@gmail.com)

### Contribute 

You can contribute to JPBC in a number of ways. 
The most obvious way is to report bugs or request new features on GitHub that would make CloudCrypto a better library.

## How to Use?

Please see test codes in package com.example.
