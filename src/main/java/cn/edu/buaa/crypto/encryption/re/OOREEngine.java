package cn.edu.buaa.crypto.encryption.re;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/4/5.
 *
 * Generic Online/Offline Revocation Encryption engine.
 */
public abstract class OOREEngine extends REEngine {
    protected OOREEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    /**
     * Offline Key Encryption Algorithm for RE
     * @param publicKey public key
     * @param n number of revocation identity set
     * @return session key / offline ciphertext pair associated with n
     */
    public abstract PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n);

    /**
     * Online Key Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @return session key / ciphertext pair associated with the revocation identity set
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] ids);

    public abstract PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] ids, Element message);
}
