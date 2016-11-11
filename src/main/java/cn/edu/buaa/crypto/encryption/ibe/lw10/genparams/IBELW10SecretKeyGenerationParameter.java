package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10SecretKeyGenerationParameter extends KeyGenerationParameters {

    private IBELW10MasterSecretKeySerParameter masterSecretKeyParameters;
    private IBELW10PublicKeySerParameter publicKeyParameters;
    private String id;

    public IBELW10SecretKeyGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (IBELW10MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (IBELW10PublicKeySerParameter)publicKeyParameters;
        this.id = id;
    }

    public IBELW10MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public IBELW10PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() {
        return this.id;
    }

}
