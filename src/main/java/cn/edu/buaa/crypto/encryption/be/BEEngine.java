package cn.edu.buaa.crypto.encryption.be;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Broadcast encryption engine.
 */
public abstract class BEEngine extends Engine {
    protected BEEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    /**
     * Setup Algorithm for BE
     * @param pairingParameters pairingParameters
     * @param maxUser maximal number of users
     * @return public key / master secret key pair of the scheme
     */
    public abstract PairingKeySerPair setup(PairingParameters pairingParameters, int maxUser);

    /**
     * Secret Key Generation Algorithm for BE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param index user index
     * @return secret key for the user with the given index
     */
    public abstract PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int index);

    /**
     * Encryption Algorithm for BE
     * @param publicKey public key
     * @param indexSet the set of indexes
     * @param message the message in GT
     * @return ciphertext for the index set
     */
    public abstract PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[] indexSet, Element message);

    /**
     * Key Encapsulation Algorithm for BE
     * @param publicKey public key
     * @param indexSet the set of indexes
     * @return header / session key pair.
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[] indexSet);

    /**
     * Decryption Algorithm for BE
     * @param publicKey public key
     * @param secretKey secret key associated with an index
     * @param indexSet the set of indexes
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    public abstract Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                       int[] indexSet, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException;

    /**
     * Key Decapsulation Algorithm for BE
     * @param publicKey public key
     * @param secretKey secret key associated with an index
     * @param indexSet the set of indexes
     * @param header ciphertext
     * @return the session key
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    public abstract byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                         int[] indexSet, PairingCipherSerParameter header) throws InvalidCipherTextException;
}
