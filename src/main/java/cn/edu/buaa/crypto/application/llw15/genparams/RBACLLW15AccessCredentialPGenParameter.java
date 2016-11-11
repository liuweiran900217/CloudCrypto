package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/19.
 *
 * Patient access credential generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15AccessCredentialPGenParameter extends KeyGenerationParameters {
    private RBACLLW15MasterSecretKeySerParameter masterSecretKeyParameters;
    private RBACLLW15PublicKeySerParameter publicKeyParameters;
    private RBACLLW15IntermediateSerParameter intermediateParameters;
    private String id;

    public RBACLLW15AccessCredentialPGenParameter(
            AsymmetricKeySerParameter publicKeyParameters,
            AsymmetricKeySerParameter masterSecretKeyParameters,
            String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        this.id = id;
        //do not use intermediate parameters
        this.intermediateParameters = null;
    }

    public RBACLLW15AccessCredentialPGenParameter(AsymmetricKeySerParameter publicKeyParameters,
                                                  AsymmetricKeySerParameter masterSecretKeyParameters,
                                                  PairingCipherSerParameter intermediateParameters,
                                                  String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
        this.id = id;
        //use intermediate parameters
        this.intermediateParameters = (RBACLLW15IntermediateSerParameter)intermediateParameters;
    }

    public RBACLLW15MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public boolean isIntermediateGeneration() {
        return (this.intermediateParameters != null);
    }

    public RBACLLW15IntermediateSerParameter getIntermediateParameters() {
        return this.intermediateParameters;
    }

    public String getId() { return id; }

}
