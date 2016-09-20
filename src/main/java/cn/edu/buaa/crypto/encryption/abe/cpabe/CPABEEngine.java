package cn.edu.buaa.crypto.encryption.abe.cpabe;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Ciphertext-Policy Attribute-Based Encryption Engine.
 * All CP-ABE scheme should implement this engine.
 */
public abstract class CPABEEngine {
    private static final AccessControlEngine default_access_control_engine = AccessTreeEngine.getInstance();
    protected AccessControlEngine accessControlEngineInstance = default_access_control_engine;

    public void setAccessControlEngine(AccessControlEngine accessControlEngine) {
        this.accessControlEngineInstance = accessControlEngine;
    }

    /**
     * Setup Algorithm for CP-ABE
     * @param rBitLength Zr Bit Length, ignore if the scheme is based on composite-order bilinear groups
     * @param qBitLength q Bit Length
     * @return public key / master secret key pair of the scheme
     */
    public abstract AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength);

    /**
     * Secret Key Generation Algorithm for CP-ABE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param attributeSet associated attribute set
     * @return secret key associated with the attribute set
     */
    public abstract CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] attributeSet);

    /**
     * Key Encapsulation Algorithm for CP-ABE
     * @param publicKey public key
     * @param accessPolicy associated access policy, given by string
     * @return session key / ciphertext pair associated with the access policy
     * @throws PolicySyntaxException  if error occurs when parsing the access policy string
     */
    public PairingKeyEncapsulationPair encryption(CipherParameters publicKey, String accessPolicy) throws PolicySyntaxException {
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
    public abstract PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, int[][] accessPolicyIntArrays, String[] rhos);

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
    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey,
                                String accessPolicy, CipherParameters ciphertext) throws PolicySyntaxException, InvalidCipherTextException {
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
    public abstract byte[] decapsulation (CipherParameters publicKey, CipherParameters secretKey,
                                          int[][] accessPolicyIntArrays, String[] rhos, CipherParameters ciphertext) throws InvalidCipherTextException;

}
