package cn.edu.buaa.crypto.chameleonhash.kr00b;

import org.bouncycastle.crypto.CipherParameters;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * interface for classes implementing algorithms modeled similar to the Krawczyk-Rabin Chameleon hash based on Discrete Log.
 */
public interface KR00b {
    /**
     * initialise the chameleon digest for hash computing or hash collision finding.
     *
     * @param forCollisionFind true if we are find a collision, false otherwise.
     * @param param key parameters for chameleon hash generation.
     */
    void init(boolean forCollisionFind, CipherParameters param);

    /**
     * compute the chameleon hash result.
     *
     * @param message the message to be hashed.
     * @return three big integers representing chameleon hash, message hash in Z_q, r, respectively.
     */
    BigInteger[] computeHash(byte[] message);

    /**
     * compute the chameleon hash result with the given randomness r
     *
     * @param message the message to be hashed.
     * @param r the randomness r that was previously used to compute.
     * @return three big integers representing chameleon hash, message hash in Z_q, r, respectively.
     */
    BigInteger[] computeHash(byte[] message, BigInteger r);

    /**
     * find r', such that Ch(pk, m', r') = Ch(pk, m, r)
     *
     * @param messagePrime the message that was supposed to find collision.
     * @param message the original message.
     * @param hash chameleon hash
     * @param r the auxiliary random parameter r.
     * @return three big integers representing chameleon hash, m' hash in Z_q, r', respectively.
     */
    BigInteger[] findCollision(byte[] messagePrime, BigInteger message, BigInteger hash, BigInteger r);
}
