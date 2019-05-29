package cn.edu.buaa.crypto.encryption.re;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
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

public abstract class REEngine extends Engine {
    protected REEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    /**
     * Setup Algorithm for RE
     * @param pairingParameters Pairing Parameters
     * @return public key / master secret key pair of the scheme
     */
    public abstract PairingKeySerPair setup(PairingParameters pairingParameters);

    /**
     * Secret Key Generation Algorithm for RE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    public abstract PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id);

    /**
     * Encryption Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @param message the message in GT
     * @return ciphertext associated with the revocation identity set ids
     */
    public abstract PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message);

    /**
     * Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @return header / session key pair
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids);

    /**
     * Decryption Algorithm for RE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param ids revocation identity set associated with the ciphertext
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    public abstract Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                       String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException;

    /**
     * Decryption Algorithm for RE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param ids revocation identity set associated with the ciphertext
     * @param header header
     * @return session key
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    public abstract byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                       String[] ids, PairingCipherSerParameter header) throws InvalidCipherTextException;
}
