package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15AccessCredentialMSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu role-based access control medical staff's session key decapsulation parameter.
 */
public class RBACLLW15DecapsulationMParameter implements CipherParameters {
    private RBACLLW15PublicKeySerParameter publicKeyParameters;
    private RBACLLW15AccessCredentialMSerParameter accessCredentialMParameters;
    private String id;
    private String[] roles;
    private String time;
    private RBACLLW15EncapsulationSerParameter encapsulationParameters;

    public RBACLLW15DecapsulationMParameter(
            AsymmetricKeySerParameter publicKeyParameters,
            AsymmetricKeySerParameter accessCredentialMParameters,
            String id,
            String[] roles,
            String time,
            PairingCipherSerParameter encapsulationParameters) {
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        this.accessCredentialMParameters = (RBACLLW15AccessCredentialMSerParameter)accessCredentialMParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.id = id;
        this.roles = roles;
        this.time = time;
        this.encapsulationParameters = (RBACLLW15EncapsulationSerParameter)encapsulationParameters;
    }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public RBACLLW15AccessCredentialMSerParameter getSecretKeyParameters() {
        return this.accessCredentialMParameters;
    }

    public RBACLLW15EncapsulationSerParameter getCiphertextParameters() {
        return this.encapsulationParameters;
    }

    public String getId() { return this.id; }

    public String[] getRoles() { return this.roles; }

    public String getRoleAt(int index) { return this.roles[index]; }

    public String getTime() { return this.time; }
}