package cn.edu.buaa.crypto.encryption.hibe;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * Hierarchical Identity-Based Encryption Engine.
 * All instances should implement this Interface.
 */
public interface HIBEEngine {
    /**
     * Setup Algorithm for HIBE
     * @param rBitLength Zr Bit Length, ignore if the scheme is based on composite-order bilinear groups
     * @param qBitLength q Bit Length
     * @param maxDepth maximal depth of hierarchy, ignore if the scheme is unbounded
     * @return public key / master secret key pair of the scheme
     */
    AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxDepth);

    /**
     * Secret Key Generation Algorithm for HIBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param ids associated identity vector
     * @return secret key associated with the identity vector ids
     */
    CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String... ids);

    /**
     * Secret Key Delegation Algorithm for HIBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector ids
     * @param id delegated identity
     * @return secret key associated with the identity vector (ids, id)
     */
    CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, String id);

    /**
     * Key Encapsulation Algorithm for HIBE
     * @param publicKey public key
     * @param ids an identity vector
     * @return session key / ciphertext pair associated with the identity vector ids
     */
    PairingKeyEncapsulationSerPair encapsulation(CipherParameters publicKey, String... ids);

    /**
     * Key Decapsulation Algorithm for HIBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector
     * @param ids identity vector associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] ids,
            CipherParameters ciphertext
    ) throws InvalidCipherTextException;
}
