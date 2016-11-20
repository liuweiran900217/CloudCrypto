package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07MasterSecretPairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicPairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;


/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE secret key generation parameter.
 */
public class CPABEBSW07SecretKeyGenerationParameter extends KeyGenerationParameters {
    private CPABEBSW07PublicPairingKeySerParameter publicKeyParameters;
    private CPABEBSW07MasterSecretPairingKeySerParameter masterSecretKeySerParameter;
    private String[] attributes;

    public CPABEBSW07SecretKeyGenerationParameter(CipherParameters publicKeyParameters,
                                                  CipherParameters masterSecretKeyParameters, String[] attributes) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.publicKeyParameters = (CPABEBSW07PublicPairingKeySerParameter)publicKeyParameters;
        this.masterSecretKeySerParameter = (CPABEBSW07MasterSecretPairingKeySerParameter)masterSecretKeyParameters;
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public CPABEBSW07PublicPairingKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public CPABEBSW07MasterSecretPairingKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeySerParameter; }

    public String[] getAttributes() { return this.attributes; }
}