package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aMasterSecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption secret key generation parameter.
 */
public class RELSW10aSecretKeyGenerationParameter extends KeyGenerationParameters {
    private RELSW10aMasterSecretKeySerParameter masterSecretKeyParameters;
    private RELSW10aPublicKeySerParameter publicKeyParameters;
    private String id;

    public RELSW10aSecretKeyGenerationParameter(CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters, String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (RELSW10aMasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (RELSW10aPublicKeySerParameter)publicKeyParameters;
        this.id = id;
    }

    public RELSW10aMasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RELSW10aPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() { return this.id; }
}
