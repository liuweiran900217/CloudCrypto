package cn.edu.buaa.crypto.encryption.ibe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * Identity-Based Encryption was formally defined and constructed by Boneh and Franklin in BF-01-CRYPTO.
 *
 * This interface is an abstract of IBE definitions.
 */
public interface IBEEngine {
    /**
     * Setup Algorithm for IBE
     * @param pairingParameters pairingParameters
     * @return public key / master secret key pair of the scheme
     */
    AsymmetricKeySerPair setup(PairingParameters pairingParameters);

    /**
     * Secret Key Generation Algorithm for IBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String id);

    /**
     * Key Encapsulation Algorithm for IBE
     * @param publicKey public key
     * @param id an identity
     * @return session key / ciphertext pair associated with the identity id
     */
    PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String id);

    /**
     * Key Decapsulation Algorithm for IBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param id identity associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
            String id, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException;
}
