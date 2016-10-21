package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Medical staff generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialMGenParameters extends KeyGenerationParameters {
    private RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters;
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private RBACLLW15IntermediateParameters intermediateParameters;
    private String[] roles;
    private String time;

    public RBACLLW15AccessCredentialMGenParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] roles, String time) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = new String[roles.length];
        System.arraycopy(roles, 0, this.roles, 0, this.roles.length);
        this.roles = roles;
        this.time = time;
        //do not use intermediate parameters
        this.intermediateParameters = null;
    }

    public RBACLLW15AccessCredentialMGenParameters(
            CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters,
            CipherParameters intermediateParameters, String[] roles, String time) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = roles;
        this.time = time;
        //use intermediate parameters
        this.intermediateParameters = (RBACLLW15IntermediateParameters)intermediateParameters;
    }

    public RBACLLW15MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getRoleAt(int index) {
        return this.roles[index];
    }

    public String[] getRoles() {
        return roles;
    }

    public String getTime() { return this.time; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameters != null);
    }

    public RBACLLW15IntermediateParameters getIntermediateParameters() {
        return this.intermediateParameters;
    }
}