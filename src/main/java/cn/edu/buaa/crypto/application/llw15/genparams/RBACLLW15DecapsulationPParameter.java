package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15AccessCredentialPSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu role-based access control patient's session key decapsulation parameter.
 */
public class RBACLLW15DecapsulationPParameter implements CipherParameters {
    private RBACLLW15PublicKeySerParameter publicKeyParameters;
    private RBACLLW15AccessCredentialPSerParameter accessCredentialPParameters;
    private String[] roles;
    private String time;
    private String id;
    private RBACLLW15EncapsulationSerParameter encapsulationParameters;

    public RBACLLW15DecapsulationPParameter(
            AsymmetricKeySerParameter publicKeyParameters,
            AsymmetricKeySerParameter accessCredentialPParameters,
            String id,
            String[] roles,
            String time,
            CipherParameters encapsulationParameters) {
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        this.accessCredentialPParameters = (RBACLLW15AccessCredentialPSerParameter)accessCredentialPParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = roles;
        this.time = time;
        this.id = id;
        this.encapsulationParameters = (RBACLLW15EncapsulationSerParameter)encapsulationParameters;
    }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public RBACLLW15AccessCredentialPSerParameter getSecretKeyParameters() {
        return this.accessCredentialPParameters;
    }

    public RBACLLW15EncapsulationSerParameter getCiphertextParameters() {
        return this.encapsulationParameters;
    }

    public String[] getRoles() { return this.roles; }

    public String getRolesAt(int index) { return this.roles[index]; }

    public String getId() { return this.id; }

    public String getTime() { return this.time; }
}