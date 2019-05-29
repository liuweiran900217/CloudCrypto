package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Medical staff generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialMGenParameter extends PairingKeyGenerationParameter {
    private RBACLLW15IntermediateSerParameter intermediateParameter;
    private String[] roles;
    private String time;

    public RBACLLW15AccessCredentialMGenParameter(
            PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter masterSecretKeyParameter,
            String[] roles, String time) {
        super(publicKeyParameter, masterSecretKeyParameter);
        assert(roles.length == ((RBACLLW15PublicKeySerParameter)publicKeyParameter).getMaxRoleNumber());
        this.roles = roles;
        this.time = time;
        //do not use intermediate parameters
        this.intermediateParameter = null;
    }

    public RBACLLW15AccessCredentialMGenParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter,
            PairingCipherSerParameter intermediateParameter, String[] roles, String time) {
        super(publicKeyParameter, masterSecretKeyParameter);
        assert(roles.length == ((RBACLLW15PublicKeySerParameter)publicKeyParameter).getMaxRoleNumber());
        this.roles = roles;
        this.time = time;
        //use intermediate parameters
        this.intermediateParameter = (RBACLLW15IntermediateSerParameter)intermediateParameter;
    }

    public String getRoleAt(int index) {
        return this.roles[index];
    }

    public String[] getRoles() {
        return roles;
    }

    public String getTime() { return this.time; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameter != null);
    }

    public RBACLLW15IntermediateSerParameter getIntermediateParameters() {
        return this.intermediateParameter;
    }
}