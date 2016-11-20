package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;


/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE secret key generation parameter.
 */
public class CPABEBSW07SecretKeyGenerationParameter extends KeyGenerationParameters {
    private CPABEBSW07PublicKeySerParameter publicKeyParameters;
    private CPABEBSW07MasterSecretKeySerParameter masterSecretKeySerParameter;
    private String[] attributes;

    public CPABEBSW07SecretKeyGenerationParameter(CipherParameters publicKeyParameters,
                                                  CipherParameters masterSecretKeyParameters, String[] attributes) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.publicKeyParameters = (CPABEBSW07PublicKeySerParameter)publicKeyParameters;
        this.masterSecretKeySerParameter = (CPABEBSW07MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public CPABEBSW07PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public CPABEBSW07MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeySerParameter; }

    public String[] getAttributes() { return this.attributes; }
}