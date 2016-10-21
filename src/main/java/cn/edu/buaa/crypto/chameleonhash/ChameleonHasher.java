package cn.edu.buaa.crypto.chameleonhash;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Chameleon hash scheme interface
 */
public interface ChameleonHasher {

    /**
     * Initialise the chameleon hasher for finding a collision or computing a hash result.
     *
     * @param forCollisionFind true if for finding a hash collision, false otherwise
     * @param param necessary parameters.
     */
    void init(boolean forCollisionFind, CipherParameters param);

    /**
     * update the internal digest with the byte b
     */
    void update(byte b);

    /**
     * update the internal digest with the byte array in
     */
    void update(byte[] in, int off, int len);

    /**
     * compute the chameleon hash for the message we've been loaded with using the key we were initialised with.
     */
    byte[] computeHash() throws CryptoException, DataLengthException;

    /**
     * compute the chameleon hash for the message we've been loaded with using the key we were initialised with,
     * and the chameleon hash result (with randomness r) that were previously used to compute.
     */
    byte[] computeHash(byte[] cHashResult) throws CryptoException, DataLengthException;

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    byte[] findCollision(byte[] cHashResult);

    /**
     * reset the internal state
     */
    void reset();

    boolean isEqualHash(byte[] cHashResult, byte[] anCHashResult);
}
