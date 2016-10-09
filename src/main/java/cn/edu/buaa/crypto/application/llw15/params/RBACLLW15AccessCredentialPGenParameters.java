package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Patient access credential generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialPGenParameters extends KeyGenerationParameters {
    private RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters;
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private RBACLLW15IntermediateParameters intermediateParameters;
    private String id;

    public RBACLLW15AccessCredentialPGenParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String id) {
        super(null, PairingUtils.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        this.id = id;
        //do not use intermediate parameters
        this.intermediateParameters = null;
    }

    public RBACLLW15AccessCredentialPGenParameters(CipherParameters publicKeyParameters,
                                                   CipherParameters masterSecretKeyParameters,
                                                   CipherParameters intermediateParameters,
                                                   String id) {
        super(null, PairingUtils.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        this.id = id;
        //use intermediate parameters
        this.intermediateParameters = (RBACLLW15IntermediateParameters)intermediateParameters;
    }

    public RBACLLW15MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameters != null);
    }

    public RBACLLW15IntermediateParameters getIntermediateParameters() {
        return this.intermediateParameters;
    }

    public String getId() { return id; }

}
