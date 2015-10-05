package cn.edu.buaa.crypto.encryption.ibe;

import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/10/5.
 */
public interface IBEEngine {

    /**
     * Setup Algorithm for IBE
     * @param rBitLength Zr Bit Length, ignore if the scheme is based on composite-order bilinear groups
     * @param qBitLength q Bit Length
     * @return public key / master secret key pair of the scheme
     */
    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength);

    /**
     * Secret Key Generation Algorithm for IBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String id);

    /**
     * Key Encapsulation Algorithm for IBE
     * @param publicKey public key
     * @param id an identity
     * @return session key / ciphertext pair associated with the identity id
     */
    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String id);

    /**
     * Key Decapsulation Algorithm for IBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector
     * @param id identity associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    public byte[] decapsulation (
            CipherParameters publicKey,
            CipherParameters secretKey,
            String[] id,
            CipherParameters ciphertext
    ) throws InvalidCipherTextException;
}
