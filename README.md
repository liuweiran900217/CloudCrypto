# CloudCrypto

Cryptographic primitive implementations for secure Cloud Storage / Computing applications. 

## Introduction

Traditional public key cryptographic primitives (e.g., Diffie-Hellman, RSA, ElGamals) have been widely applied in practice to secure network and storage systems. However, such schemes have limited functionalities. Researches have been made to propose advancaed cryptographic primitives and schemes to meet the functionality and security needs for cloud storage / computing paradigms.

**CloudCrypto** project aims at implementing advanced cryptographic schemes under the well-designed Java Cryptographic Architecture (JCA). To achieve this target, **CloudCrypto** leverages [Bouncy Castle](http://www.bouncycastle.org/java.html) as the underlying library, which strictly follows JCA standard. In general, Java seems not a good choice for Crypto implementations due to runtime effiency. 
We choose Java as the programming language since Java provides good portability so that **CloudCrypto** can be even **directly** port to mobile and / or other embedded devices, e.g., Android. 

We are providing the source code of **CloudCrypto** with no license fee. It is open source and free to use for Research & Development purpose. 

We are glad to notice that Medica Corp. is experimenting with **CloudCrypto** for Research & Development purpose. 

## Develop Environments

**CloudCrypto** is buit using Maven 2. Please see `pom.xml` for the dependent libiraries. In its current version, **CloudCrypto** leverages the following libraries:

- [Bouncy Castle](http://www.bouncycastle.org/java.html): supporting basic cryptographic primitives, e.g., hash functions, symmetric encryption schemes.
- [jPBC Library](http://gas.dia.unisa.it/projects/jpbc/): supporting bilinear groups.
- [JUnit](http://junit.org/junit4/): for unit test.
- [Standard Input and Output Libraries by Princeton University](http://algs4.cs.princeton.edu/code/): an easy-to-use standard input and output library from the Princeton open course *Introduction to Programming: An Interdisciplinary Approach*. We only leverages `In.java`, `Out.java`, `StdIn.java`, `StdOut.java`, `BinaryIn.java`, `BinaryOut.java`. Therefore, we directly include these files in our project. You can find the source code under the package `/src/main/java/edu/princeton/cs/algs4`.

## Pairing-Based Cryptographic Primitives

In its current verion, **CloudCrypto** mainly focuses on implementing schemes based on Bilinear Groups. The underlying algebric library is [Java Pairing-Based Cryptography Library](http://gas.dia.unisa.it/projects/jpbc/). 

### Challenges 

There are some schemes implementations in Java Pairing-Based Cryptography, but with the following issues:

- No avaiable serialization methods.
- The encryption scheme implementations indeed encrypt a random element in G\_T, while there is no reasonable methods that can map messages / plaintexts to elements in G\_T in an one-to-one manner. That is, one cannot decrypt the ciphertext, get the elemment in G\_T, and map it back to the original message.

### Our Solutions

In our implementations, we leverage the built-in Java serialization method, allowing serializing any CipherParameters  to byte arrays. This allows users to further upload the generated CipherParameters to public Clouds. Any objects whose name ends with `SerParameter` supports serialization. The following method in `src/main/java/cn/edu/buaa/crypto/utils/PairingUtils.java`shows how to serialize / deserizalie these objects:

	public static byte[] SerCipherParameter(CipherParameters cipherParameters) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(cipherParameters);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        byteArrayOutputStream.close();
        return byteArray;
    }

We provide a key encapsulation mechanisms for encryption schemes, i.e., the encryption algorithm encapsulates a random session key, by which the encryptor can use to encrypt arbitrary data using symmetric encryption schemes, i.e., AES, TwoFish. 

### Object `PairingParameters`

The most important object for invoking pairing-based cryptographic schemes is `PairingParameters`, which belongs to jPBC library that provides all necessary information for bilinear groups. Note that it is a littie bit complicated to correctly generate such parameters without knowing necessary backgrounds about bilinear groups. We have pre-generated some parameters, all of which can be found at `/params`. We list some of the parameters used in our unit tests:

- `a_80_256.properties`: Type A prime-order bilinear groups with 80-bit Z_p and 256-bit G. Note that the group order cannot meet the security needs for today's system. This parameters can only be used for testing the correctness of the scheme implementations.
- `a_160_512.properties`: Type A prime-order bilinear groups with 160-bit Z_p and 512-bit G. 
- `a1_3_128.properties` : Type A1 composite-order bilinear groups with 3 prime factors, all of which have size 128-bit. Note that the group order cannnot meet the security needs for today's sstem. This parameter can only be used for testing the correctness of the scheme implementations.
- `a1_3_512.properties`: Type A1 composite-order bilinear groups with 3 prime factors, all of which have size 512-bit.
- `f_160.properties`: Type F prime-order bilinear groups with 160-bit Z_p. Note that this group is an asymmetric bilinear group so that it can be only used for schemes built on asymmetric bilinear groups. We recommend using this properties for the Boneh-Lynn-Shacham short signature scheme.

The following code shows how to get PairingParameters from files in /params:

	//Obtain PairingParameters from /params/a_160_512.properties
    PairingParameters pairingParameters = PairingFactory.getPairingParameters("params/a_160_512.properties");

## Algebric Algorithms
	
### Linear Secret Sharing Scheme

Linear secret sharing scheme (LSSS) is the generalization of Shamir secret sharing scheme, which is one of the most famous cryptographic primitives proposed by Shamir in 1979 (See paper [*How To Share a Secret*](http://dl.acm.org/citation.cfm?id=359176)). In 1996, Beimel introduced the concept of LSSS, showing that Shamir's scheme can be seen as a special case for LSSS (See thesis [*Secret Schemes for Secret Sharing and Key Distribution*](https://www.cs.bgu.ac.il/~beimel/Papers/thesis.pdf)). Nowadays, LSSS has been a basic primitive to construct access control mechanism in Attribute-Based Encryption (ABE) systems.

We implemented two forms of access control mechanism by LSSS, one is based on the original Shamir's scheme. The other one is based on the construction by Waters and Lewko (See [full version](https://eprint.iacr.org/2010/351.pdf) of the paper [*Decentralizing Attribute-Based Encryption*](http://link.springer.com/chapter/10.1007%2F978-3-642-20465-4_31), Appendix G).

The following code shows how to construct and use access control mechanism using LSSS. The access tree is represented by int\[\]\[\], see the comment in the [source code](https://dsl-external.bbn.com/svn/openP3S/trunk/jmiracl-crypto/src/main/java/com/bbn/projects/spar/p3s/jmiracl/crypto/utils/LSSS.java) on how to represent access tree by int\[\]\[\].

    Pairing pairing = PairingFactory.getPairing(pairingParameters);
    //note that Lewko-Waters LSSS do not support threshold gate access control.
    int[][] accessPolicy = {
            {2,2,1,2},
            {2,2,3,4},
            {4,3,-7,-8,-9,-10},
            {2,2,-2,5},
            {3,2,-4,-5,-6},
            {2,1,-1,-3}
    };
    // rhos can be arbitrary strings
    String[] rhos = new String[] {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
    String[] satisfiedRhos = new String[] {"2", "3", "5", "6", "7", "9", "10"};
    //Using access tree
    AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();
    try {
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
        //secret sharing
        Element secret = pairing.getZr().newRandomElement().getImmutable();
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, secret, accessControlParameter);

        //Secret reconstruction
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, satisfiedRhos, accessControlParameter);
        Element reconstructedSecret = pairing.getZr().newZeroElement().getImmutable();
        for (String eachAttribute : satisfiedRhos) {
            if (omegaElementsMap.containsKey(eachAttribute)) {
                reconstructedSecret = reconstructedSecret.add(lambdaElementsMap.get(eachAttribute).mulZn(omegaElementsMap.get(eachAttribute))).getImmutable();
            }
        }
        Assert.assertEquals(secret, reconstructedSecret);
    } catch (UnsatisfiedAccessControlException e) {
        // throw if the given attribute set does not satisfy the access policy represented by accress tree.
    }

The following code shows how to construct and use access control mechanism using LSSS, where the access policy is represented by a String.

    Pairing pairing = PairingFactory.getPairing(pairingParameters);
    String accessPolicyString = "((0 and 1 and 2) and (3 or 4 or 5) and (6 and 7 and (8 or 9 or 10 or 11)))";
    String[] satisfiedRhos = new String[] {"0", "1", "2", "4", "6", "7", "10"};
    //Using Lewko-Waters LSSS
    AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();
    try {
        //parse access policy
        int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
        //secret sharing
        Element secret = pairing.getZr().newRandomElement().getImmutable();
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, secret, accessControlParameter);

        //Secret reconstruction
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, satisfiedRhos, accessControlParameter);
        Element reconstructedSecret = pairing.getZr().newZeroElement().getImmutable();
        for (String eachAttribute : satisfiedRhos) {
            if (omegaElementsMap.containsKey(eachAttribute)) {
                reconstructedSecret = reconstructedSecret.add(lambdaElementsMap.get(eachAttribute).mulZn(omegaElementsMap.get(eachAttribute))).getImmutable();
            }
        }
        Assert.assertEquals(secret, reconstructedSecret);
    } catch (UnsatisfiedAccessControlException e) {
        // throw if the given attribute set does not satisfy the access policy represented by accress tree.
    } catch (PolicySyntaxException e) {
        // throw if invalid access policy representation.
    }

### Horner's Rule under Z_p

Given the product $\prod\limits_{i = 1}^n {({b_i}x + 1)}$, find the coefficients $a_n, a_{n-1}, \cdots, a_1, a_0$ such that
${a_n}{x^n} + {a_{n - 1}}{x^{n - 1}} +  \cdots  + {a_1}x + {a_0} = \prod\limits_{i = 1}^n {({b_i}x + 1)}$.

This algorithm is called Horner's Rule, which is previously used to efficiently evaluate n-degree polynomials. 
The Horner's Rule can be used to compute the above coefficients. The detailed algorithm is shown in the paper [*Fully Homomorphic Encryption with Relatively Small Key and Ciphertext Sizes*](http://link.springer.com/chapter/10.1007%2F978-3-642-13013-7_25).

The following code shows how to use Horner's rule to comupte the coefficients:

    Pairing pairing = PairingFactory.getPairing(pairingParameters);
    //randomly generate 10 bi's
    Element[] bs = new Element[10];
    for (Element bi : bs) {
        bi = pairing.getZr().newRandomElement().getImmutable();
    }
    //the resulting ai's
    Element[] as = HornerRule.ComputeEfficients(pairing, bs);

## Basic Cryptographic Primitives

### Public Key Signatures

We implemented three secure signature schemes based built on bilinear groups:

- Boneh-Lynn-Shacham short signature scheme (`BLS01Signer`, see paper [*Short Signatures from the Weil Pairing*](http://link.springer.com/chapter/10.1007/3-540-45682-1_30));
- Boneh-Boyen short signatures (`BB04Signer`, see paper [*Short Signatures Without Random Oracles*](http://link.springer.com/chapter/10.1007/978-3-540-24676-3_4));
- Boneh-Boyen improved short signatures (`BB08Signer`, see paper [*Short Signatures Without Random Oracles and the SDH Assumption in Bilinear Groups*](http://link.springer.com/article/10.1007/s00145-007-9005-7));

The following code shows how to use Boneh-Boyen signatures under the JCA standard:

	//replace the BB04 related objects to others (BLS01, BB08) to use other signature schemes

	//generate public key / secret key pair
    PairingKeyPairGenerator signKeyPairGenerator = new BB04SignKeyPairGenerator();
    signKeyPairGenerator.init(new BB04SignKeyPairGenerationParameter(pairingParameters));
    PairingKeySerPair keyPair = signKeyPairGenerator.generateKeyPair();
    PairingKeySerParameter publicKey = keyPair.getPublic();
    PairingKeySerParameter secretKey = keyPair.getPrivate();

    try {
        //sign
        Signer signer = new PairingDigestSigner(new BB04Signer(), new SHA256Digest());
        byte[] message = "Message".getBytes();
        signer.init(true, secretKey);
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();

        //verify
        signer.init(false, publicKey);
        signer.update(message, 0, message.length);
        if (!signer.verifySignature(signature)) {
            System.out.println("cannot verify valid signature abort...");
            System.exit(0);
        }
    } catch (CryptoException e) {
        //useless, just for satisfying JCA standard
    }

Note that the signature of the Boneh-Boyen-04 scheme and the Boneh-Boyen-08 scheme are serialized using ASN1 encodings. 
This is because the signature results contain at least two Elements so that we need to leverage an encoding method to distinct Elements.

The most important feature of the Boneh-Lynn-Shacham scheme is that the resulting signature length can be short. 
To achieve this feature, we use toBytesCompressed() in CurveElement to compress the Element, and serialize it without using any encoding methods. 
Further, we recommend leveraging it using Type F curve (with PairingParameters shown in /params/f_160.properties). 
The resulting signature length can be short. In fact, for Type F curve with r bit length 160, the signature length is 21 bytes, i.e., 168 bits.

For detailed information, please see the implemention shown in BLS01Signer. 

We thank an anonymous employee from Medica Corp. for offering solutions for shortening the byte array length of Element. 

### Chameleon Hash Functions

We implemented the Discrete-Log-based chameleon hash function proposed by Krawczyk and Rabin. (`DLogKR00bHasher.java`, see paper [*Chameleon Signatures*](https://www.mendeley.com/catalog/chameleon-signatures/)). Note that in 2016, me, Jianwei Liu, Qianhong Wu, Bo Qin and Kaitai Liang introduced the concept of Universal collision-resistant chameleon hash function (See paper [*Online/Offline Public-Index Predicate Encryption for Fine-Grained Mobile Access Control*](http://link.springer.com/chapter/10.1007/978-3-319-45741-3_30)). We also implemented the universal collision-resistant chamelon hash based on the Krawczyk-Rabin chameleoin hash, see `DLogKR00bUniversalHasher.java`.

The JUnit test example is in `src/test/java/com/example/chameleonhash/ChameleonHasherJUnitTest.java`.

We follow the standard `RFC3526` to build DLog groups used for DLog-based chameleon hash functions, see `src/main/java/cn/edu/buaa/crypto/algebra/serparams/SecurePrimeSerParameter.java` for detailed information.

## Advanced Cryptographic Primitives

### Broadcast Encryption (BE)

We implemented Boneh-Gentry-Waters BE scheme (`BEBGW05Engine`, see paper [*Collusion Resistant Broadcast Encryption with Short Ciphertexts and Private Keys*](http://link.springer.com/chapter/10.1007/11535218_16)). 

See `src/test/java/com/example/encryption/be/BEEngineJUnitTest.java` for JUnit test example.

### Identity-Based Encryption (IBE)

We implemented several IBE schemes:

- Boneh-Franklin CPA-secure IBE scheme (`IBEBF01aEngine`, see paper [*Identity-Based Encryption from the Weil Pairing*](http://link.springer.com/chapter/10.1007/3-540-44647-8_13));
- Boneh-Franklin CPA-secure IBE scheme (`IBEBF01bEngine`, see paper [*Identity-Based Encryption from the Weil Pairing*](http://link.springer.com/chapter/10.1007/3-540-44647-8_13));
- Gentry CPA-secure IBE scheme (`IBEGen06aEngine`, see paper [*Practical Identity-Based Encryption Without Random Oracles*](http://link.springer.com/chapter/10.1007/11761679_27));
- Gentry CCA2-secure IBE scheme (`IBEGen06bEngine`, see paper [*Practical Identity-Based Encryption Without Random Oracles*](http://link.springer.com/chapter/10.1007/11761679_27));
- Lewko-Waters CPA-secure IBE scheme built on composite-order bilinear groups (`IBELW10Engine`, see paper [*New Techniques for Dual System Encryption and Fully Secure HIBE with Short Ciphertexts*](http://link.springer.com/chapter/10.1007/978-3-642-11799-2_27));

See `src/test/java/com/example/encryption/ibe/IBEEngineJUnitTest` for JUnit test example.

### Hierarchical Identity-Based Encryption (HIBE)

We implemented two HIBE schemes:

- Boneh-Boyen HIBE scheme (`HIBEBB04Engine`, see paper [*Efficient Selective-ID Secure Identity-Based Encryption Without Random Oracles*](http://link.springer.com/chapter/10.1007/978-3-540-24676-3_14));
- Boneh-Boyen-Goh HIBE scheme (`HIBEBBG05Engine`, see paper [*Hierarchical Identity Based Encryption with Constant Size Ciphertext*](http://link.springer.com/chapter/10.1007/11426639_26));

See `src/test/java/com/example/encryption/hibe/HIBEEngineJUnitTest` for JUnit test example.

### Identity-Based Broadcast Encryption (IBBE)

We implemented Delerablée IBBE scheme (`IBBEDel07Engine`, see paper [*Identity-Based Broadcast Encryption with Constant Size Ciphertexts and Private Keys*](http://link.springer.com/chapter/10.1007/978-3-540-76900-2_12)). 

See `src/test/java/com/example/encryption/ibbe/IBBEEngineJUnitTest` for JUnit test example.

### Hierarchical Identity-Based Broadcast Encryption (HIBBE)

The concept of HIBBE was proposed by me, Prof. Jianwei Liu, Prof. Qianhong Wu, and Dr. Bo Qin in 2014. We further proposed and implemented several HIBBE schemes:

- CPA-secure HIBBE built on composite-order bilinear groups (`HIBBELLW14Engine`, see paper [*Hierarchical Identity-Based Broadcast Encryption*](http://link.springer.com/chapter/10.1007/978-3-319-08344-5_16));
- CPA-secure HIBBE built on prime-order bilinear groups (`HIBBELLW16aEngine`, see paper [*Practical chosen-ciphertext secure Hierarchical Identity-Based Broadcast Encryption*](http://link.springer.com/article/10.1007/s10207-015-0287-8));
- CCA2-secure HIBBE built on prime-order bilinear groups (`HIBBELLW16bEngine`, see paper [*Practical chosen-ciphertext secure Hierarchical Identity-Based Broadcast Encryption*](http://link.springer.com/article/10.1007/s10207-015-0287-8));
- CCA2-secure HIBBE built on composite-order bilinear groups (`HIBBELLW17Engine`, the paper has been submitted to *Soft Computing*, under review, minr revision);

See `src/test/java/com/example/encryption/hibbe/HIBBEEngineJUnitTest` for JUnit test example.

### Revocation Encryption (RE)

The concept of RE was proposed by Lewko and Waters. We implemented serverl RE schemes:

- Lewko-Waters RE scheme version 1 (`RELSW10aEngine`, see paper [*Revocation Systems with Very Small Private Keys*](http://ieeexplore.ieee.org/abstract/document/5504791/));
- CPA-secure online/offline RE scheme constructed by me, Jianwei Liu, Qianhong Wu, Bo Qin and Kaitai Liang (`RELLW16aEngine`, see paper [*Online/Offline Public-Index Predicate Encryption for Fine-Grained Mobile Access Control*](http://link.springer.com/chapter/10.1007/978-3-319-45741-3_30)).
- CCA2-secure online/offline RE scheme constructed by me, Jianwei Liu, Qianhong Wu, Bo Qin and Kaitai Liang (`RELLW16bEngine`, see paper [*Online/Offline Public-Index Predicate Encryption for Fine-Grained Mobile Access Control*](http://link.springer.com/chapter/10.1007/978-3-319-45741-3_30)).

See `src/test/java/com/example/encryption/re/REEngineJUnitTest` for JUnit test example.

### Attribute-Based Encryption (ABE)

We implemented several ABE schemes, including Key-Policy setting (KP-ABE) and Ciphertext-Policy setting (CP-ABE). KP-ABE includes:

- Goyal-Pandey-Sahai-Waters small-universe KP-ABE (`KPABEGPSW06aEngine`, see paper [*Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data*](http://dl.acm.org/citation.cfm?id=1180418));
- Goyal-Pandey-Sahai-Waters large-universe KP-ABE (`KPABEGPSW06bEngine`, see paper [*Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data*](http://dl.acm.org/citation.cfm?id=1180418));
- Rouselakis-Waters large-universe KP-ABE (`KPABERW13Engine`, see paper [*Practical Constructions and New Proof Methods for Large Universe Attribute-Based Encryption*](http://dl.acm.org/citation.cfm?id=2516672));
- Hohenberger-Waters online/offline KP-ABE (`OOKPABEHW14Engine`, see paper [*Online/Offline Attribute-Based Encryption*](http://link.springer.com/chapter/10.1007/978-3-642-54631-0_17));
- CCA2-secure KP-ABE proposed by me, Jianwei Liu, Qianhong Wu, and Bo Qin (`KPABELLW14Engine`, see paper [*Practical Direct Chosen Ciphertext Secure Key-Policy Attribute-Based Encryption with Public Ciphertext Test*](http://link.springer.com/chapter/10.1007/978-3-319-11212-1_6));
- CCA2-secure online/offline KP-ABE proposed by me, Jianwei Liu, Qianhong Wu, Bo Qin and Kaitai Liang (`OOKPABELLW16Engine`, see paper [*Online/Offline Public-Index Predicate Encryption for Fine-Grained Mobile Access Control*](http://link.springer.com/chapter/10.1007/978-3-319-45741-3_30)).

CP-ABE includes:

- Bethencourt-Sahai-Waters large-universe CP-ABE (`CPABEBSW07Engine`, see paper [*Ciphertext-Policy Attribute-Based Encryption*](http://ieeexplore.ieee.org/abstract/document/4223236/));
- Rouselakis-Waters large-universe CP-ABE (`CPABERW13Engine`, see paper [*Practical Constructions and New Proof Methods for Large Universe Attribute-Based Encryption*](http://dl.acm.org/citation.cfm?id=2516672));
- Hohenberger-Waters online/offline CP-ABE (`OOCPABEHW14Engine`, see paper [*Online/Offline Attribute-Based Encryption*](http://link.springer.com/chapter/10.1007/978-3-642-54631-0_17));
- CCA2-secure CP-ABE proposed by me, Jianwei Liu, Qianhong Wu, and Bo Qin (`KPABELLW14Engine`, the paper is in the manuscript form);
- CCA2-secure online/offline KP-ABE proposed by me, Jianwei Liu, Qianhong Wu, Bo Qin and Kaitai Liang (`OOKPABELLW16Engine`, see paper [*Online/Offline Public-Index Predicate Encryption for Fine-Grained Mobile Access Control*](http://link.springer.com/chapter/10.1007/978-3-319-45741-3_30)).

See `src/test/java/com/example/encryption/abe/KPABEEngineJUnitTest` and `src/test/java/com/example/encryption/abe/CPABEEngineJUnitTest` for JUnit test example.

### Self-Extractable Predicate Encryption (SEPE)

The concept of SEPE was introduced by Bo Qin, me, Jianwei Liu and Qianhong Wu. The paper has been submitted to *The 37th IEEE International Conference on Distributed Computing Systems (ICDCS 2017)*, under review.

Respectively see JUnit test examples in different kinds of encryption schemes under package `src/test/java/com/example/encryption/`.

## Contact

CloudCrypto is mainly developed by Weiran Liu.

Feel free to contact me at [footman_900217@126.com](mailto:footman_900217@126.com), or at [liuweiran900217@gmail.com](mailto:liuweiran900217@gmail.com). 

I can receive the emails from both mailboxs. I would mainly reply the emails using 126 since sometimes it would be difficult to reply emails using Gmail from China.