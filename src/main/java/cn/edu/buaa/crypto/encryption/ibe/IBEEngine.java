package cn.edu.buaa.crypto.encryption.ibe;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * Identity-Based Encryption was formally defined and constructed by Boneh and Franklin in BF-01-CRYPTO.
 *
 * This interface is an abstract of IBE definitions.
 */
public interface IBEEngine extends Engine {
    /**
     * Setup Algorithm for IBE
     * @param pairingParameters pairingParameters
     * @return public key / master secret key pair of the scheme
     */
    PairingKeySerPair setup(PairingParameters pairingParameters);

    /**
     * Secret Key Generation Algorithm for IBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id);

    /**
     * Encryption Algorithm for IBE
     * @param publicKey public key
     * @param id an identity
     * @param message the message in GT
     * @return ciphertext associated with the identity id
     */
    PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String id, Element message);

    /**
     * Key Encapsulation Algorithm for IBE
     * @param publicKey public key
     * @param id an identity
     * @return header / session key pair.
     */
    PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id);

    /**
     * Decryption Algorithm for IBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param id identity associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                        String id, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException;

    /**
     * Key Decapsulation Algorithm for IBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param id identity associating with the ciphertext
     * @param header ciphertext
     * @return the session key
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                        String id, PairingCipherSerParameter header) throws InvalidCipherTextException;
}
