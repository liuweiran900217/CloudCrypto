package cn.edu.buaa.crypto.application.llw15.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by liuweiran on 16/5/19.
 */
public class RBACLLW15DecapsulationPParameters implements CipherParameters {
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private RBACLLW15AccessCredentialPParameters accessCredentialPParameters;
    private String[] roles;
    private String time;
    private String id;
    private RBACLLW15EncapsulationParameters encapsulationParameters;

    public RBACLLW15DecapsulationPParameters(
            CipherParameters publicKeyParameters,
            CipherParameters accessCredentialPParameters,
            String id,
            String[] roles,
            String time,
            CipherParameters encapsulationParameters) {
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        this.accessCredentialPParameters = (RBACLLW15AccessCredentialPParameters)accessCredentialPParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = Arrays.copyOf(roles, roles.length);
        this.time = new String(time);
        this.id = new String(id);
        this.encapsulationParameters = (RBACLLW15EncapsulationParameters)encapsulationParameters;
    }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public RBACLLW15AccessCredentialPParameters getSecretKeyParameters() {
        return this.accessCredentialPParameters;
    }

    public RBACLLW15EncapsulationParameters getCiphertextParameters() {
        return this.encapsulationParameters;
    }

    public String[] getRoles() { return Arrays.copyOf(roles, roles.length); }

    public String getRolesAt(int index) { return this.roles[index]; }

    public String getId() { return this.id; }

    public String getTime() { return this.time; }
}