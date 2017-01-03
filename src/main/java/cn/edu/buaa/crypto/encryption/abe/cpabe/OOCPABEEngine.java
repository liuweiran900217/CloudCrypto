package cn.edu.buaa.crypto.encryption.abe.cpabe;

import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
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
     * @return intermedaite ciphertext associated with n
     */
    public abstract PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n);

    /**
     * Online Key Encapsulation Algorithm
     * @param publicKey public key
     * @param intermediate intermediate ciphertext
     * @param accessPolicyIntArrays access policy
     * @param rhos rhos
     * @return session key / ciphertext pair associated with the access policy and rhos
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, int[][] accessPolicyIntArrays, String[] rhos);

    public PairingKeyEncapsulationSerPair encapsulation(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String accessPolicy) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return encapsulation(publicKey, intermediate, accessPolicyIntArrays, rhos);
    }

    /**
     * Encryption Algorithm for CP-ABE
     * @param publicKey public key
     * @param intermediate intermediate ciphertext
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos associated rhos, given by string array
     * @param message the message in GT
     * @return ciphertext associated with the access policy and rhos
     */
    public abstract PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
                                                         int[][] accessPolicyIntArrays, String[] rhos, Element message);

    public PairingCipherSerParameter encryption(
            PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate,
            String accessPolicy, Element message) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return encryption(publicKey, intermediate, accessPolicyIntArrays, rhos, message);
    }

}
