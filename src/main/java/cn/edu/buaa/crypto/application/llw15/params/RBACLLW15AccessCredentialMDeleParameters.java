package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by liuweiran on 16/5/19.
 */
public class RBACLLW15AccessCredentialMDeleParameters extends KeyGenerationParameters {
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private RBACLLW15AccessCredentialMParameters accessCredentialMParameters;
    private int index;
    private String delegateRole;

    public RBACLLW15AccessCredentialMDeleParameters(
            CipherParameters publicKeyParameters,
            CipherParameters accessCredentialMParameters,
            int index, String role) {
        super(null, RBACLLW15Engine.STENGTH);
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        this.accessCredentialMParameters = (RBACLLW15AccessCredentialMParameters)accessCredentialMParameters;
        assert(this.accessCredentialMParameters.getRoleAt(index) == null);
        this.index = index;
        this.delegateRole = role;
    }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public RBACLLW15AccessCredentialMParameters getAccessCredentialMParameters() { return this.accessCredentialMParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateRole() { return this.delegateRole; }

}
