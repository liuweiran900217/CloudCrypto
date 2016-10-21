package cn.edu.buaa.crypto.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Generic HIBE Engine.
 */
public interface HIBBEEngine {

    /**
     * Setup Algorithm for HIBBE
     * @param rBitLength Zr Bit Length, ignore if the scheme is based on composite-order bilinear groups
     * @param qBitLength q Bit Length
     * @param maxUser maximal size of users, ignore if the scheme is unbounded
     * @return public key / master secret key pair of the scheme
     */
    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxUser);

        /**
         * Secret Key Generation Algorithm for HIBBE
         * @param publicKey public key
         * @param masterKey master secret key
         * @param ids associated identity vector
         * @return secret key associated with the identity vector ids
         */
        public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] ids);

        /**
         * Secret Key Delegation Algorithm for HIBBE
         * @param publicKey public key
         * @param secretKey secret key associated with an identity vector ids
         * @param index delegated identity index
         * @param id delegated identity
         * @return secret key associated with the identity vector (ids, id)
         */
        public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, int index, String id);

        /**
         * Key Encapsulation Algorithm for HIBBE
         * @param publicKey public key
         * @param ids an identity vector set
         * @return session key / ciphertext pair associated with the identity vector set ids
         */
        public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String[] ids);

        /**
         * Key Decapsulation Algorithm for HIBBE
         * @param publicKey public key
         * @param secretKey secret key associated with an identity vector
         * @param ids identity vector set associated with the ciphertext
         * @param ciphertext ciphertext
         * @return the decapsulated session key
         * @throws InvalidCipherTextException if the decapsulation procedure is failure
         */
        public byte[] decapsulation (
                CipherParameters publicKey,
                CipherParameters secretKey,
                String[] ids,
                CipherParameters ciphertext
        ) throws InvalidCipherTextException;
}
