package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu role-based access control medical staff's session key decapsulation parameter.
 */
public class RBACLLW15DecapsulationMParameter extends PairingDecryptionGenerationParameter {
    private String id;
    private String[] roles;
    private String time;

    public RBACLLW15DecapsulationMParameter(
            PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter accessCredentialMParameter,
            String id,
            String[] roles,
            String time,
            PairingCipherSerParameter encapsulationParameter) {
        super(publicKeyParameter, accessCredentialMParameter, encapsulationParameter);
        assert(roles.length == ((RBACLLW15PublicKeySerParameter)publicKeyParameter).getMaxRoleNumber());
        this.id = id;
        this.roles = roles;
        this.time = time;
    }

    public String getId() { return this.id; }

    public String[] getRoles() { return this.roles; }

    public String getRoleAt(int index) { return this.roles[index]; }

    public String getTime() { return this.time; }
}