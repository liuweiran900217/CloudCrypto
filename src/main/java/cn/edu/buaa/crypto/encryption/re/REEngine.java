package cn.edu.buaa.crypto.encryption.re;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
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
    PairingKeySerPair setup(PairingParameters pairingParameters);

    /**
     * Secret Key Generation Algorithm for RE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id);

    /**
     * Encryption Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @param message the message in GT
     * @return ciphertext associated with the revocation identity set ids
     */
    PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message);

    /**
     * Decryption Algorithm for RE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param ids revocation identity set associated with the ciphertext
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                       String[] ids, PairingCipherSerParameter ciphertext
    ) throws InvalidCipherTextException;
}
