package cn.edu.buaa.crypto.encryption.abe.cpabe;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Online / Offline CP-ABE engine.
 * All OO-CP-ABE scheme should implement this engine.
 */
public abstract class OOCPABEEngine extends CPABEEngine {
    protected OOCPABEEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    /**
     * Offline Key Encapsulation Algorithm
     * @param publicKey public key
     * @param n maximal number of ciphertext attribute
     * @return session key / offline ciphertext pair associated with n
     */
    public abstract PairingKeyEncapsulationSerPair offlineEncapsulation(PairingKeySerParameter publicKey, int n);

    /**
     * Online Key Encapsulation Algorithm
     * @param publicKey public key
     * @param iCiphertext intermediate ciphertext
     * @param accessPolicyIntArrays access policy
     * @param rhos rhos
     * @return session key / ciphertext pair associated with the revocation identity set
     */
    public abstract PairingKeyEncapsulationSerPair onlineEncapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter iCiphertext, int[][] accessPolicyIntArrays, String[] rhos);

    /**
     * Encryption Algorithm for CP-ABE
     * @param publicKey public key
     * @param iCiphertext intermediate ciphertext
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos associated rhos, given by string array
     * @param message the message in GT
     * @return ciphertext associated with the access policy
     */
    public abstract PairingCipherSerParameter encryption(PairingCipherSerParameter iCiphertext,
            PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message);

}
