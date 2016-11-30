package cn.edu.buaa.crypto.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Generic HIBE Engine.
 */
public interface HIBBEEngine extends Engine {

    /**
     * Setup Algorithm for HIBBE
     * @param pairingParameters PairingParameters
     * @param maxUser maximal size of users, ignore if the scheme is unbounded
     * @return public key / master secret key pair of the scheme
     */
    PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser);

    /**
     * Secret Key Generation Algorithm for HIBBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param ids associated identity vector
     * @return secret key associated with the identity vector ids
    */
    PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] ids);

    /**
     * Secret Key Delegation Algorithm for HIBBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector ids
     * @param index delegated identity index
     * @param id delegated identity
     * @return secret key associated with the identity vector (ids, id)
    */
    PairingKeySerParameter delegate(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, int index, String id);

    /**
     * Encryption Algorithm for HIBBE
     * @param publicKey public key
     * @param ids an identity vector set
     * @param message the message in GT
     * @return ciphertext associated with the identity vector set ids
    */
    PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message);

    /**
     * Encapsulation Algorithm for HIBBE
     * @param publicKey public key
     * @param ids an identity vector set
     * @return header / session key pair
     */
    PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids);

    /**
     * Decryption Algorithm for HIBBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector
     * @param ids identity vector set associated with the ciphertext
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws InvalidCipherTextException if the decryption procedure is failure
    */
    Element decryption (PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException;

    /**
     * Decapsulation Algorithm for HIBBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector
     * @param ids identity vector set associated with the ciphertext
     * @param header header
     * @return the session key
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, String[] ids, PairingCipherSerParameter header)
            throws InvalidCipherTextException;
}
