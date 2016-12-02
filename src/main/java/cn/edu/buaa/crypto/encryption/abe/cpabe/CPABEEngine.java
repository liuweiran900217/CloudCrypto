package cn.edu.buaa.crypto.encryption.abe.cpabe;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Ciphertext-Policy Attribute-Based Encryption Engine.
 * All CP-ABE scheme should implement this engine.
 */
public abstract class CPABEEngine extends Engine {
    protected AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    protected CPABEEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

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
     * Encryption Algorithm for CP-ABE
     * @param publicKey public key
     * @param accessPolicy associated access policy, given by string
     * @param message the message in GT
     * @return ciphertext associated with the access policy
     * @throws PolicySyntaxException  if error occurs when parsing the access policy string
     */
    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String accessPolicy, Element message) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return encryption(publicKey, accessPolicyIntArrays, rhos, message);
    }

    /**
     * Encryption Algorithm for CP-ABE
     * @param publicKey public key
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos associated rhos, given by string array
     * @param message the message in GT
     * @return ciphertext associated with the access policy
     */
    public abstract PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message);

    /**
     * Encapsulation Algorithm for CP-ABE
     * @param publicKey public key
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos associated rhos, given by string array
     * @return header / session key
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos);

    /**
     * Decryption Algorithm for CP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an attribute set
     * @param accessPolicy access policy associating with the ciphertext, given by string
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws PolicySyntaxException if error occurs when parsing the access policy string
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String accessPolicy, PairingCipherSerParameter ciphertext)
            throws PolicySyntaxException, InvalidCipherTextException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return decryption(publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext);
    }

    /**
     * Decryption Algorithm for CP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an attribute set
     * @param accessPolicyIntArrays access policy associating with the ciphertext, given by 2D int arrays
     * @param rhos rhos associating with the ciphertext, given by string array
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    public abstract Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                          int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException;

    /**
     * Decapsulation Algorithm for CP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an attribute set
     * @param accessPolicyIntArrays access policy associating with the ciphertext, given by 2D int arrays
     * @param rhos rhos associating with the ciphertext, given by string array
     * @param header header
     * @return session key
     * @throws InvalidCipherTextException if the decryption procedure is failure
     */
    public abstract byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                       int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException;
}
