package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicPairingKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE ciphertext generation parameter.
 */
public class CPABEBSW07CiphertextGenerationParameter {
    private CPABEBSW07PublicPairingKeySerParameter publicKeyParameters;
    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;

    public CPABEBSW07CiphertextGenerationParameter(
            AccessControlEngine accessControlEngines, CipherParameters publicKeyParameters,
            int[][] accessPolicy, String[] rhos) {
        this.accessControlEngine = accessControlEngines;
        this.publicKeyParameters = (CPABEBSW07PublicPairingKeySerParameter)publicKeyParameters;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public AccessControlEngine getAccessControlEngine() {
        return this.accessControlEngine;
    }

    public CPABEBSW07PublicPairingKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }
}
