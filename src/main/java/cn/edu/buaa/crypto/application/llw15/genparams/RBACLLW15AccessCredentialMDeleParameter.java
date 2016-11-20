package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15AccessCredentialMSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Medical staff access credential delegation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialMDeleParameter extends PairingKeyDelegationParameter {
    private RBACLLW15IntermediateSerParameter intermediateParameter;
    private int index;
    private String delegateRole;

    public RBACLLW15AccessCredentialMDeleParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter accessCredentialMParameter,
            int index, String role) {
        super(publicKeyParameter, accessCredentialMParameter);
        assert(((RBACLLW15AccessCredentialMSerParameter)accessCredentialMParameter).getRoleAt(index) == null);
        this.index = index;
        this.delegateRole = role;
        //do not use indermerdiate parameters
        this.intermediateParameter = null;
    }

    public RBACLLW15AccessCredentialMDeleParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter accessCredentialMParameter,
            PairingCipherSerParameter intermediateParameter, int index, String role) {
        super(publicKeyParameter, accessCredentialMParameter);
        assert(((RBACLLW15AccessCredentialMSerParameter)accessCredentialMParameter).getRoleAt(index) == null);
        this.index = index;
        this.delegateRole = role;
        //use indermerdiate parameters
        this.intermediateParameter = (RBACLLW15IntermediateSerParameter)intermediateParameter;
    }

    public int getIndex() { return this.index; }

    public String getDelegateRole() { return this.delegateRole; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameter != null);
    }

    public RBACLLW15IntermediateSerParameter getIntermediateParameters() {
        return this.intermediateParameter;
    }

}
