package cn.edu.buaa.crypto.encryption.abe.kpabe;

import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Key-Policy Attribute-Based Encryption Engine.
 * All KP-ABE scheme should implement this engine.
 */
public abstract class KPABEEngine {
    // Default strength for KeyPairGenerator, useless in Pairing based cryptography
    private static final int STENGTH = 12;

    /**
     * Setup Algorithm for KP-ABE
     * @param rBitLength Zr Bit Length, ignore if the scheme is based on composite-order bilinear groups
     * @param qBitLength q Bit Length
     * @return public key / master secret key pair of the scheme
     */
    public abstract AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength);

    /**
     * Secret Key Generation Algorithm for KP-ABE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param accessPolicy associated access policy, given by strings
     * @return secret key associated with the access policy
     * @throws PolicySyntaxException if error occurs when parsing the access policy string
     */
    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String accessPolicy) throws PolicySyntaxException {
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
    public abstract CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, int[][] accessPolicyIntArrays, String[] rhos);

    /**
     * Key Encapsulation Algorithm for KP-ABE
     * @param publicKey public key
     * @param attributeSet associated attribute set
     * @return session key / ciphertext pair associated with the attribute set
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(CipherParameters publicKey, String[] attributeSet);

    /**
     * Key Decapsulation Algorithm for KP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an access policy
     * @param attributeSet attribute set associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    public abstract byte[] decapsulation (CipherParameters publicKey, CipherParameters secretKey,
                                 String[] attributeSet, CipherParameters ciphertext) throws InvalidCipherTextException;
}
