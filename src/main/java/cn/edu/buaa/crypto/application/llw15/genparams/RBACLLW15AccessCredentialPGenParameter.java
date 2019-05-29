package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Patient access credential generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialPGenParameter extends PairingKeyGenerationParameter {
    private RBACLLW15IntermediateSerParameter intermediateParameter;
    private String id;

    public RBACLLW15AccessCredentialPGenParameter(
            PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter masterSecretKeyParameter,
            String id) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.id = id;
        //do not use intermediate parameters
        this.intermediateParameter = null;
    }

    public RBACLLW15AccessCredentialPGenParameter(PairingKeySerParameter publicKeyParameter,
                                                  PairingKeySerParameter masterSecretKeyParameter,
                                                  PairingCipherSerParameter intermediateParameter,
                                                  String id) {

        //use intermediate parameters
        super(publicKeyParameter, masterSecretKeyParameter);
        this.id = id;
        this.intermediateParameter = (RBACLLW15IntermediateSerParameter)intermediateParameter;
    }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameter != null);
    }

    public RBACLLW15IntermediateSerParameter getIntermediateParameters() {
        return this.intermediateParameter;
    }

    public String getId() { return id; }

}
