package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.REEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption secret key generation parameter.
 */
public class RELSW10aSecretKeyGenerationParameters extends KeyGenerationParameters {
    private RELSW10AMasterSecretKeySerParameter masterSecretKeyParameters;
    private RELSW10APublicKeySerParameter publicKeyParameters;
    private String id;

    public RELSW10aSecretKeyGenerationParameters(CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters, String id) {
        super(null, REEngine.STENGTH);
        this.masterSecretKeyParameters = (RELSW10AMasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (RELSW10APublicKeySerParameter)publicKeyParameters;
        this.id = id;
    }

    public RELSW10AMasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RELSW10APublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() { return this.id; }
}
