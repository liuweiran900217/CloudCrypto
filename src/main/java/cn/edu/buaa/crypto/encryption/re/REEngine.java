package cn.edu.buaa.crypto.encryption.re;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/4/3.
 *
 * Revocable Encryption was formally defined and constructed by Lewko and Waters in LW-10-SP
 *
 * This interface is an abstract definition of RE.
 */

public interface REEngine extends Engine {
    /**
     * Setup Algorithm for RE
     * @param pairingParameters Pairing Parameters
     * @return public key / master secret key pair of the scheme
     */
    AsymmetricKeySerPair setup(PairingParameters pairingParameters);

    /**
     * Secret Key Generation Algorithm for RE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String id);

    /**
     * Key Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @return session key / ciphertext pair associated with the revocation identity set ids
     */
    PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String... ids);

    /**
     * Key Decapsulation Algorithm for RE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param ids revocation identity set associated with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
                          String[] ids, PairingCipherSerParameter ciphertext
    ) throws InvalidCipherTextException;
}
