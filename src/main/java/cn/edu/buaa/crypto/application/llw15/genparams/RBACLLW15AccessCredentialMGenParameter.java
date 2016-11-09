package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Medical staff generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialMGenParameter extends KeyGenerationParameters {
    private RBACLLW15MasterSecretKeySerParameter masterSecretKeyParameters;
    private RBACLLW15PublicKeySerParameter publicKeyParameters;
    private RBACLLW15IntermediateSerParameter intermediateParameters;
    private String[] roles;
    private String time;

    public RBACLLW15AccessCredentialMGenParameter(
            AsymmetricKeySerParameter publicKeyParameters,
            AsymmetricKeySerParameter masterSecretKeyParameters,
            String[] roles, String time) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = new String[roles.length];
        System.arraycopy(roles, 0, this.roles, 0, this.roles.length);
        this.roles = roles;
        this.time = time;
        //do not use intermediate parameters
        this.intermediateParameters = null;
    }

    public RBACLLW15AccessCredentialMGenParameter(
            AsymmetricKeySerParameter publicKeyParameters, AsymmetricKeySerParameter masterSecretKeyParameters,
            PairingCipherSerParameter intermediateParameters, String[] roles, String time) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = roles;
        this.time = time;
        //use intermediate parameters
        this.intermediateParameters = (RBACLLW15IntermediateSerParameter)intermediateParameters;
    }

    public RBACLLW15MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

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

    public RBACLLW15IntermediateSerParameter getIntermediateParameters() {
        return this.intermediateParameters;
    }
}