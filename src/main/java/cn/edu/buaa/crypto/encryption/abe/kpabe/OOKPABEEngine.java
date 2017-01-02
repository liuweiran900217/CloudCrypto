package cn.edu.buaa.crypto.encryption.abe.kpabe;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Online / Offline KP-ABE engine.
 * All OO-KP-ABE scheme should implement this engine.
 */
public abstract class OOKPABEEngine extends KPABEEngine {
    protected OOKPABEEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    /**
     * Offline Key Encapsulation Algorithm
     * @param publicKey public key
     * @param n maximal number of ciphertext attribute
     * @return intermedaite ciphertext associated with n
     */
    public abstract PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n);

    /**
     * online encryption algorithm for KP-ABE
     * @param publicKey public key
     * @param intermediate intermediate ciphertext
     * @param attributes associated attribute set
     * @param message message in GT
     * @return ciphertext associated with the attribute set
     */
    public abstract PairingCipherSerParameter encryption(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            String[] attributes, Element message);

    /**
     * online encapsulation algorithm for KP-ABE
     * @param publicKey public key
     * @param intermediate intermediate ciphertext
     * @param attributes associated attribute set
     * @return header / session key pair
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] attributes);
}
