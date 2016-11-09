package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu role-based access control key encapsulation generation parameters.
 */
public class RBACLLW15EncapsulationGenParameter implements CipherParameters {
    private RBACLLW15PublicKeySerParameter publicKeyParameters;
    private RBACLLW15IntermediateSerParameter intermediateParameters;
    private String id;
    private String[] roles;
    private String time;

    public RBACLLW15EncapsulationGenParameter(
            AsymmetricKeySerParameter publicKeyParameters, String id, String[] roles, String time) {
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = roles;
        this.id = id;
        this.time = time;
        //do not use intermediate parameters
        this.intermediateParameters = null;
    }

    public RBACLLW15EncapsulationGenParameter(
            AsymmetricKeySerParameter publicKeyParameters, PairingCipherSerParameter intermediateParameters,
            String id, String[] roles, String time) {
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        assert(roles.length == this.publicKeyParameters.getMaxRoleNumber());
        this.roles = roles;
        this.id = id;
        this.time = time;
        //use intermediate parameters
        this.intermediateParameters = (RBACLLW15IntermediateSerParameter)intermediateParameters;
    }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getRoles() { return this.roles; }

    public String getRoleAt(int index) { return this.roles[index]; }

    public String getId() { return this.id; }

    public String getTime() { return this.time; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameters != null);
    }

    public RBACLLW15IntermediateSerParameter getIntermediateParameters() {
        return this.intermediateParameters;
    }
}
