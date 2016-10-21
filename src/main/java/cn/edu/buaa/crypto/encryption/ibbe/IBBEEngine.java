package cn.edu.buaa.crypto.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/8/23.
 *
 * Identity-Based Broadcast Encryption Engine.
 * All instances should implement this Interface.
 */
public interface IBBEEngine {
    // Default strength for KeyPairGenerator, useless in Pairing based cryptography
    int STENGTH = 12;

    /**
     * Setup Algorithm for IBBE
     * @param rBitLength Zr Bit Length, ignore if the scheme is based on composite-order bilinear groups
     * @param qBitLength q Bit Length
     * @param maxBroadcastReceiver maximal broadcast receivers, ignore if the scheme is unbounded
     * @return public key / master secret key pair of the scheme
     */
    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxBroadcastReceiver);

    /**
     * Secret Key Generation Algorithm for IBBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String id);

    /**
     * Key Encapsulation Algorithm for IBBE
     * @param publicKey public key
     * @param ids a broadcast identity set
     * @return session key / ciphertext pair associated with the broadcast identity set ids
     */
    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids);

    /**
     * Key Decapsulation Algorithm for IBBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param ids broadcast identity set associating with the ciphertext
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
