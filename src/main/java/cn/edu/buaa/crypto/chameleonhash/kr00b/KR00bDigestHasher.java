package cn.edu.buaa.crypto.chameleonhash.kr00b;

import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/20.
 *
 *
 */
public class KR00bDigestHasher implements ChameleonHasher {
    private final Digest digest;
    private final KR00b kr00bHasher;
    private boolean forCollisionFind;

    public KR00bDigestHasher(KR00b hasher, Digest digest) {
        this.digest = digest;
        this.kr00bHasher = hasher;
    }

    public void init(boolean forCollisionFind, CipherParameters parameters)
    {
        this.forCollisionFind = forCollisionFind;
        AsymmetricKeyParameter k = (AsymmetricKeyParameter)parameters;

        if (forCollisionFind && !k.isPrivate()) {
            throw new IllegalArgumentException("Finding Collision Requires Private Key.");
        }

        if (!forCollisionFind && k.isPrivate()) {
            throw new IllegalArgumentException("Hash Computation Requires Public Key.");
        }

        reset();

        kr00bHasher.init(forCollisionFind, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(byte input) {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(byte[]  input, int inOff, int length) {
        digest.update(input, inOff, length);
    }

    public byte[] computeHash() throws CryptoException, DataLengthException {
        if (forCollisionFind) {
            throw new IllegalStateException("KR00bDigestHasher not initialised for hash computing");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        BigInteger[] cHashResult = kr00bHasher.computeHash(hash);
        try {
            return derEncode(cHashResult[0], cHashResult[1], cHashResult[2]);
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode chameleon hash for m");
        }
    }

    public byte[] computeHash(byte[] cHashResult) throws CryptoException, DataLengthException {
        if (forCollisionFind) {
            throw new IllegalStateException("KR00bDigestHasher not initialised for hash computing");
        }
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        BigInteger[] cHash;
        try {
            cHash = derDecode(cHashResult);
        } catch (IOException e) {
            throw new IllegalStateException("unable to decode chameleon hash for m");
        }
        BigInteger[] cHashPrime = kr00bHasher.computeHash(hash, cHash[2]);
        if (!cHashPrime[1].equals(cHash[1])) {
            throw new IllegalStateException("the input r is not used previously to compute chameleon hash m");
        }
        try {
            return derEncode(cHashPrime[0], cHashPrime[1], cHashPrime[2]);
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode chameleon hash for m");
        }
    }

    public byte[] findCollision(byte[] chameleonHashResult) {
        if (!forCollisionFind) {
            throw new IllegalStateException("KR00DigestHasher not initialised for collision finding.");
        }

        byte[] mPrime = new byte[digest.getDigestSize()];
        digest.doFinal(mPrime, 0);

        BigInteger[] cHash;
        try {
            cHash = derDecode(chameleonHashResult);
        } catch (IOException e) {
            throw new IllegalStateException("unable to decode chameleon hash for m");
        }

        BigInteger[] cHashPrime = kr00bHasher.findCollision(mPrime, cHash[1], cHash[0], cHash[2]);
        try {
            return derEncode(cHashPrime[0], cHashPrime[1], cHashPrime[2]);
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode chameleon hash for m'");
        }
    }

    public void reset()
    {
        digest.reset();
    }

    public boolean isEqualHash(byte[] cHashResult, byte[] anCHashResult) {
        BigInteger[] cHash1, cHash2;
        try {
            cHash1 = derDecode(cHashResult);
            cHash2 = derDecode(anCHashResult);
        } catch (IOException e) {
            throw new IllegalStateException("unable to decode chameleon hash for m");
        }
        return cHash1[0].equals(cHash2[0]);
    }

    private byte[] derEncode(BigInteger cHashResult, BigInteger hashResult, BigInteger r) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(cHashResult));
        v.add(new ASN1Integer(hashResult));
        v.add(new ASN1Integer(r));

        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    private BigInteger[] derDecode(byte[] encoding) throws IOException {
        ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(encoding);
        return new BigInteger[]
                {
                        ((ASN1Integer)s.getObjectAt(0)).getValue(),
                        ((ASN1Integer)s.getObjectAt(1)).getValue(),
                        ((ASN1Integer)s.getObjectAt(2)).getValue(),
                };
    }
}
