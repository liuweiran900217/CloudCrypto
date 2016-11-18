package cn.edu.buaa.crypto.encryption.abe.kpabe;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Key-Policy Attribute-Based Encryption Engine.
 * All KP-ABE scheme should implement this engine.
 */
public abstract class KPABEEngine {
    protected AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    public abstract String getEngineName();

    public void setAccessControlEngine(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
    }

    public boolean isAccessControlEngineSupportThresholdGate() {
        return this.accessControlEngine.isSupportThresholdGate();
    }

    /**
     * Setup Algorithm for KP-ABE
     * @param pairingParameters Pairing Parameters
     * @param maxAttributesNum maximal number of attributes supported, left 0 if no such limitation
     * @return public key / master secret key pair of the scheme
     */
    public abstract AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum);

    /**
     * Secret Key Generation Algorithm for KP-ABE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param accessPolicy associated access policy, given by strings
     * @return secret key associated with the access policy
     * @throws PolicySyntaxException if error occurs when parsing the access policy string
     */
    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String accessPolicy) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return keyGen(publicKey, masterKey, accessPolicyIntArrays, rhos);
    }

    /**
     * Secret Key Generation Algorithm for KP-ABE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos associated rhos, given by string array
     * @return secret key associated with the access policy
     */
    public abstract AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos);

    /**
     * Key Encapsulation Algorithm for KP-ABE
     * @param publicKey public key
     * @param attributes associated attribute set
     * @return session key / ciphertext pair associated with the attribute set
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String[] attributes);

    /**
     * Key Decapsulation Algorithm for KP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an access policy
     * @param attributes attribute set associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    public abstract byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
                                 String[] attributes, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException;
}
