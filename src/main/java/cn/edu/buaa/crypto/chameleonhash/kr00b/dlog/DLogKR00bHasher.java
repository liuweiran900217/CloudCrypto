package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.algebra.serparams.SecurePrimeSerParameter;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00b;
import org.bouncycastle.crypto.CipherParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin Chameleon hash scheme
 */
public class DLogKR00bHasher implements KR00b {
    protected DLogKR00bKeyParameters key;
    private SecureRandom random;

    /**
     * Default configuration.
     */
    public DLogKR00bHasher() {

    }

    public void init(boolean forCollisionFind, CipherParameters param) {
        if (forCollisionFind) {
            this.key = (DLogKR00bSecretKeyParameters)param;
        } else {
            this.key = (DLogKR00bPublicKeyParameters)param;
        }
        this.random = new SecureRandom();
    }

    public BigInteger[] computeHash(byte[] message) {
        BigInteger q = this.key.getParameters().getQ();
        BigInteger p = this.key.getParameters().getP();
        BigInteger g = this.key.getParameters().getG();
        BigInteger m = calculateE(q, message);
        BigInteger y = ((DLogKR00bPublicKeyParameters)this.key).getY();

        int qBitLength = q.bitLength();
        BigInteger r;
        do
        {
            r = new BigInteger(qBitLength, random);
        }
        while (r.equals(BigInteger.ZERO) || r.compareTo(q) >= 0);

        BigInteger hash = g.modPow(m, p).multiply(y.modPow(r, p)).mod(p);
        return new BigInteger[]{ hash, m, r };
    }

    public BigInteger[] computeHash(byte[] message, BigInteger r) {
        BigInteger q = this.key.getParameters().getQ();
        BigInteger p = this.key.getParameters().getP();
        BigInteger g = this.key.getParameters().getG();
        BigInteger m = calculateE(q, message);
        BigInteger y = ((DLogKR00bPublicKeyParameters)this.key).getY();

        BigInteger hash = g.modPow(m, p).multiply(y.modPow(r, p)).mod(p);
        return new BigInteger[]{ hash, m, r };
    }

    public BigInteger[] findCollision(byte[] messagePrime, BigInteger message, BigInteger hash, BigInteger r) {
        SecurePrimeSerParameter params = key.getParameters();
        BigInteger q = params.getQ();
        BigInteger mPrime = calculateE(q, messagePrime);
        BigInteger x = ((DLogKR00bSecretKeyParameters)key).getX();

        BigInteger rPrime = x.modInverse(q).multiply(message.subtract(mPrime).mod(q)).mod(q).add(r).mod(q);

        return new BigInteger[]{ hash, mPrime, rPrime };
    }

    private BigInteger calculateE(BigInteger n, byte[] message) {
        if (n.bitLength() >= message.length * 8) {
            return new BigInteger(1, message);
        } else {
            byte[] trunc = new byte[n.bitLength() / 8];

            System.arraycopy(message, 0, trunc, 0, trunc.length);

            return new BigInteger(1, trunc);
        }
    }
}
