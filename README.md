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

## Develop Environments

Similar to Java Pairing-Based Cryptography Library, 
CloudCrypto is built using Maven 2. You can download it from [http://maven.apache.org](http://maven.apache.org).

There are a few dependencies which are hosted on any publicly available Maven Repository 
so Maven will be able to resolve them automatically.
The only Jar library that you may need to download and configure by yourself is JPBC itself. 

The development enviroment is IntelliJ IDEA. In fact, the source codes is a whole IDEA project.
For the ones who want to have a try, please simply download the code and import it into IntelliJ IDEA.

## Algebra Tools

We have implemented basic algebra tools in order to be further used in cryptographic schemes.

### Horner's Rule

Given the product $\prod\limits_{i = 1}^n {({b_i}x + 1)}$, find the coefficients $a_n, a_{n-1}, \cdots, a_1, a_0$ such that
${a_n}{x^n} + {a_{n - 1}}{x^{n - 1}} +  \cdots  + {a_1}x + {a_0} = \prod\limits_{i = 1}^n {({b_i}x + 1)}$.

This algorithm is called Horner's Rule, which is previously used to efficiently evaluate n-degree polynomials. 
The Horner's Rule can be used to compute the above coefficients. The detailed algorithm is shown in 
Nigel P. Smart, Frederik Vercauteren. Fully Homomorphic Encryption with Relatively Small Key and Ciphertext Sizes. PKC 2010, pp. 420 - 443, 2010.

### Access Control Mechanism using Boolean Formula

Access control mechanism using Boolean formula is a primitive used in Attribute-based Encryption. 
There are mainly two methods to implement boolean formula access control: access tree and linear secret sharing scheme (LSSS). 
We separately implement the two methods in our toolkit. 

- Access Tree: Vipul Goyal, Omkant Pandey, Amit Sahai, Brent Waters. Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data. CCS 2006, pp. 89-87, 2006.
- LSSS: Allison Lewko, Brent Waters. Decentralizing Attribute-Based Encryption. EUROCRYPT 2011, pp. 568-588, 2011.

## Schemes

We have implemented the following schemes. We will continue implementing others.

### Revocation Systems

- Lewko-Sahai-Waters Simple Revocation Systems (Security and Privacy 2010).
- Chosen ciphertext secure Online/Offline LSW simple Revocation Systems.
    - An instance of Online/Offline Public Index Predicate Encryption, **related paper has been submitted to ESORICS 2016, under review**.

### Identity-Based Encryption

- (2016.05.07) Lewko-Waters Identity-Based Encryption scheme (TCC 2010).

### Hierarhical Identity-Based Encryption

- Boneh-Boyen Hierarchical Identity-Based Encryption scheme (EUROCRYPT 2004).
- Boneh-Boyen-Goh Hierarhical Identity-Based Encryption scheme (EUROCRYPT 2005).

### Hiererchical Identity-Based Broadcast Encryption

- (2016.05.16) Hierarchical Identity-Based Broadcast Encryption scheme.
    - **Weiran Liu**, Jianwei Liu, Qianhong Wu, Bo Qin. Hierarchical Identity-Based Broadcast Encryption. ACISP 2014, 242-257.
    - **The journal version has been submitted to "Soft Computing", under review**.
- (2016.05.17) Liu-Liu-Wu Hierarchical Identity-Based Broadcast Encryption scheme.
    - **Weiran Liu**, Jianwei Liu, Qianhong Wu, Bo Qin. Practical Chosen Ciphertext Secure Hierarhical Identity-Based Broadcast Encryption.
    International Journal of Information Security, 2016, 15(1): 35-50.

### Chameleon Hash Functions
Since the Online/Offline Predicate Encryption transformation technique 
proposed by me, Prof. Jianwei Liu, Prof. Qianhong Wu, and Dr. Bo Qin 
uses Chameleon hash as the underlying primitives, we implement some well-known Chameleon hash functions on group G_T 
for constructing instantiations of our transformation. The schemes include:

- Katz-Rabin Chameleon Hash (NDSS 2000).
- Chen-Zhang-Kim Chameleon Hash without Key Exposure (ISC 2004).

### Cryptographic Applications

- (2016.06.20) Auditing and Revocation Enabled Role-Based Access Control over Outsourced Private EHRs. 
    - **Weiran Liu**, Xiao Liu, Jianwei Liu, Jun Zhang, Yan Li. Auditing and Revocation Enabled Role-Based Access Control
    over Outsourced Private EHRs. HPCC 2015, 336-341.
    - **The journal version has been submitted to "The Computer Journal", under review**.
    
## Contact and Contribute

### Contact 

CloudCrypto is mainly developed by Weiran Liu.

Feel free to contact me at [liuweiran900217@gmail.com](mailto:liuweiran900217@gmail.com)

### Contribute 

You can contribute to JPBC in a number of ways. 
The most obvious way is to report bugs or request new features on GitHub that would make CloudCrypto a better library.

## How to Use?

Please see test codes in package com.example.
