package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15AccessCredentialMSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Medical staff access credential delegation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialMDeleParameter extends KeyGenerationParameters {
    private RBACLLW15PublicKeySerParameter publicKeyParameters;
    private RBACLLW15AccessCredentialMSerParameter accessCredentialMParameters;
    private RBACLLW15IntermediateSerParameter intermediateParameters;
    private int index;
    private String delegateRole;

    public RBACLLW15AccessCredentialMDeleParameter(
            AsymmetricKeySerParameter publicKeyParameters, AsymmetricKeySerParameter accessCredentialMParameters,
            int index, String role) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        this.accessCredentialMParameters = (RBACLLW15AccessCredentialMSerParameter)accessCredentialMParameters;
        assert(this.accessCredentialMParameters.getRoleAt(index) == null);
        this.index = index;
        this.delegateRole = role;
        //do not use indermerdiate parameters
        this.intermediateParameters = null;
    }

    public RBACLLW15AccessCredentialMDeleParameter(
            AsymmetricKeySerParameter publicKeyParameters, AsymmetricKeySerParameter accessCredentialMParameters,
            PairingCipherSerParameter intermediateParameters, int index, String role) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        this.accessCredentialMParameters = (RBACLLW15AccessCredentialMSerParameter)accessCredentialMParameters;
        assert(this.accessCredentialMParameters.getRoleAt(index) == null);
        this.index = index;
        this.delegateRole = role;
        //use indermerdiate parameters
        this.intermediateParameters = (RBACLLW15IntermediateSerParameter)intermediateParameters;
    }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public RBACLLW15AccessCredentialMSerParameter getAccessCredentialMParameters() { return this.accessCredentialMParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateRole() { return this.delegateRole; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameters != null);
    }

    public RBACLLW15IntermediateSerParameter getIntermediateParameters() {
        return this.intermediateParameters;
    }

}
