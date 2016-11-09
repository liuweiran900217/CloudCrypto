package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu EHR role-based access control encapsulation audit parameter.
 */
public class RBACLLW15EncapsulationAuditParameter implements CipherParameters {
    private RBACLLW15PublicKeySerParameter publicKeyParameters;
    private String[] roles;
    private String id;
    private String time;
    private RBACLLW15EncapsulationSerParameter encapsulationParameters;

    public RBACLLW15EncapsulationAuditParameter(
            AsymmetricKeySerParameter publicKeyParameters,
            String id,
            String[] roles,
            String time,
            CipherParameters encapsulationParameters) {
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = roles;
        this.id = id;
        this.time = time;
        this.encapsulationParameters = (RBACLLW15EncapsulationSerParameter)encapsulationParameters;
    }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public RBACLLW15EncapsulationSerParameter getCiphertextParameters() {
        return this.encapsulationParameters;
    }

    public String[] getRoles() { return this.roles; }

    public String getRolesAt(int index) { return this.roles[index]; }

    public String getId() { return this.id; }

    public String getTime() { return this.time; }
}