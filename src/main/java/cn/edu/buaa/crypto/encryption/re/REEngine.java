package cn.edu.buaa.crypto.encryption.re;

import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/4/3.
 *
 * Revocable Encryption was formally defined and constructed by Lewko and Waters in LW-10-SP
 *
 * This interface is an abstract definition of RE.
 */

public interface REEngine {

    /**
     * Setup Algorithm for RE
     * @param rBitLength Zr Bit Length, ignore if the scheme is based on composite-order bilinear groups
     * @param qBitLength q Bit Length
     * @return public key / master secret key pair of the scheme
     */
    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength);

    /**
     * Secret Key Generation Algorithm for RE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String id);

    /**
     * Key Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @return session key / ciphertext pair associated with the revocation identity set ids
     */
    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids);

    /**
     * Key Decapsulation Algorithm for RE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param ids revocation identity set associated with the ciphertext
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
