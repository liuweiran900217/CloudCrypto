package cn.edu.buaa.crypto.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
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
     * @param pairingParameters PairingParameters
     * @param maxUser maximal size of users, ignore if the scheme is unbounded
     * @return public key / master secret key pair of the scheme
     */
    AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxUser);

    /**
     * Secret Key Generation Algorithm for HIBBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param ids associated identity vector
     * @return secret key associated with the identity vector ids
    */
    AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String[] ids);

    /**
     * Secret Key Delegation Algorithm for HIBBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector ids
     * @param index delegated identity index
     * @param id delegated identity
     * @return secret key associated with the identity vector (ids, id)
    */
    AsymmetricKeySerParameter delegate(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, int index, String id);

    /**
     * Key Encapsulation Algorithm for HIBBE
     * @param publicKey public key
     * @param ids an identity vector set
     * @return session key / ciphertext pair associated with the identity vector set ids
    */
    PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String[] ids);

    /**
     * Key Decapsulation Algorithm for HIBBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity vector
     * @param ids identity vector set associated with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
    */
    byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException;
}
