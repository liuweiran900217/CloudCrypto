package cn.edu.buaa.crypto.encryption.abe.cpabe;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Ciphertext-Policy Attribute-Based Encryption Engine.
 * All CP-ABE scheme should implement this engine.
 */
public abstract class CPABEEngine {
    protected AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    public abstract String getEngineName();

    public void setAccessControlEngine(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
    }

    public boolean isAccessControlEngineSupportThresholdGate() {
        return this.accessControlEngine.isSupportThresholdGate();
    }

    /**
     * Setup Algorithm for CP-ABE
     * @param pairingParameters PairingParameters
     * @param maxAttributesNum maximal number of attributes supported, useless if no such limitation
     * @return public key / master secret key pair of the scheme
     */
    public abstract PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum);

    /**
     * Secret Key Generation Algorithm for CP-ABE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param attributes associated attribute set
     * @return secret key associated with the attribute set
     */
    public abstract PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes);

    /**
     * Key Encapsulation Algorithm for CP-ABE
     * @param publicKey public key
     * @param accessPolicy associated access policy, given by string
     * @return session key / ciphertext pair associated with the access policy
     * @throws PolicySyntaxException  if error occurs when parsing the access policy string
     */
    public PairingKeyEncapsulationSerPair encryption(PairingKeySerParameter publicKey, String accessPolicy) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return encapsulation(publicKey, accessPolicyIntArrays, rhos);
    }

    /**
     * Key Encapsulation Algorithm for CP-ABE
     * @param publicKey public key
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos associated rhos, given by string array
     * @return session key / ciphertext pair associated with the attribute set
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos);

    /**
     * Key Decapsulation Algorithm for CP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an attribute set
     * @param accessPolicy access policy associating with the ciphertext, given by string
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws PolicySyntaxException if error occurs when parsing the access policy string
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String accessPolicy, PairingCipherSerParameter ciphertext) throws PolicySyntaxException, InvalidCipherTextException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return decapsulation(publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext);
    }
    /**
     * Key Decapsulation Algorithm for CP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an attribute set
     * @param accessPolicyIntArrays access policy associating with the ciphertext, given by 2D int arrays
     * @param rhos rhos associating with the ciphertext, given by string array
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    public abstract byte[] decapsulation (PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                          int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException;

}
