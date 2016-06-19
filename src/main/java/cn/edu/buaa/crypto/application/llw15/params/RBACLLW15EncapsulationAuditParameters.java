package cn.edu.buaa.crypto.application.llw15.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by liuweiran on 16/5/19.
 */
public class RBACLLW15EncapsulationAuditParameters implements CipherParameters {
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private String[] roles;
    private String id;
    private String time;
    private RBACLLW15EncapsulationParameters encapsulationParameters;

    public RBACLLW15EncapsulationAuditParameters(
            CipherParameters publicKeyParameters,
            String id,
            String[] roles,
            String time,
            CipherParameters encapsulationParameters) {
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = Arrays.copyOf(roles, roles.length);
        this.id = new String(id);
        this.time = new String(time);
        this.encapsulationParameters = (RBACLLW15EncapsulationParameters)encapsulationParameters;
    }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public RBACLLW15EncapsulationParameters getCiphertextParameters() {
        return this.encapsulationParameters;
    }

    public String[] getRoles() { return Arrays.copyOf(roles, roles.length); }

    public String getRolesAt(int index) { return this.roles[index]; }

    public String getId() { return this.id; }

    public String getTime() { return this.time; }
}