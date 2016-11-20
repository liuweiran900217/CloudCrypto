package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncapsulationGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Liu-Liu-Wu role-based access control key encapsulation generation parameters.
 */
public class RBACLLW15EncapsulationGenParameter extends PairingEncapsulationGenerationParameter {
    private RBACLLW15IntermediateSerParameter intermediateParameter;
    private String id;
    private String[] roles;
    private String time;

    public RBACLLW15EncapsulationGenParameter(
            AsymmetricKeySerParameter publicKeyParameter, String id, String[] roles, String time) {
        super(publicKeyParameter);
        assert(roles.length == ((RBACLLW15PublicKeySerParameter)publicKeyParameter).getMaxRoleNumber());
        this.roles = roles;
        this.id = id;
        this.time = time;
        //do not use intermediate parameters
        this.intermediateParameter = null;
    }

    public RBACLLW15EncapsulationGenParameter(
            AsymmetricKeySerParameter publicKeyParameter, PairingCipherSerParameter intermediateParameter,
            String id, String[] roles, String time) {
        super(publicKeyParameter);
        assert(roles.length == ((RBACLLW15PublicKeySerParameter)publicKeyParameter).getMaxRoleNumber());
        this.roles = roles;
        this.id = id;
        this.time = time;
        //use intermediate parameters
        this.intermediateParameter = (RBACLLW15IntermediateSerParameter)intermediateParameter;
    }

    public String[] getRoles() { return this.roles; }

    public String getId() { return this.id; }

    public String getTime() { return this.time; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameter != null);
    }

    public RBACLLW15IntermediateSerParameter getIntermediateParameter() {
        return this.intermediateParameter;
    }
}
