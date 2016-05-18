package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 */
public class RBACLLW15AccessCredentialMGenParameters extends KeyGenerationParameters {
    private RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters;
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private String[] roles;
    private String time;

    public RBACLLW15AccessCredentialMGenParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] roles, String time) {
        super(null, RBACLLW15Engine.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = Arrays.copyOf(roles, roles.length);
        this.time = new String(time);
    }

    public RBACLLW15MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getRoleAt(int index) {
        return this.roles[index];
    }

    public String[] getRoles() {
        return Arrays.copyOf(roles, roles.length);
    }

    public String getTime() { return this.time; }
}