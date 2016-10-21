package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Medical staff access credential delegation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialMDeleParameters extends KeyGenerationParameters {
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private RBACLLW15AccessCredentialMParameters accessCredentialMParameters;
    private RBACLLW15IntermediateParameters intermediateParameters;
    private int index;
    private String delegateRole;

    public RBACLLW15AccessCredentialMDeleParameters(
            CipherParameters publicKeyParameters, CipherParameters accessCredentialMParameters,
            int index, String role) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        this.accessCredentialMParameters = (RBACLLW15AccessCredentialMParameters)accessCredentialMParameters;
        assert(this.accessCredentialMParameters.getRoleAt(index) == null);
        this.index = index;
        this.delegateRole = role;
        //do not use indermerdiate parameters
        this.intermediateParameters = null;
    }

    public RBACLLW15AccessCredentialMDeleParameters(
            CipherParameters publicKeyParameters, CipherParameters accessCredentialMParameters,
            CipherParameters intermediateParameters, int index, String role) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        this.accessCredentialMParameters = (RBACLLW15AccessCredentialMParameters)accessCredentialMParameters;
        assert(this.accessCredentialMParameters.getRoleAt(index) == null);
        this.index = index;
        this.delegateRole = role;
        //use indermerdiate parameters
        this.intermediateParameters = (RBACLLW15IntermediateParameters)intermediateParameters;
    }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public RBACLLW15AccessCredentialMParameters getAccessCredentialMParameters() { return this.accessCredentialMParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateRole() { return this.delegateRole; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameters != null);
    }

    public RBACLLW15IntermediateParameters getIntermediateParameters() {
        return this.intermediateParameters;
    }

}
