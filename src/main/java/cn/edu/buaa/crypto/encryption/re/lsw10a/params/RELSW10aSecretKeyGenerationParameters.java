package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.REEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class RELSW10aSecretKeyGenerationParameters extends KeyGenerationParameters {
    private RELSW10aMasterSecretKeyParameters masterSecretKeyParameters;
    private RELSW10aPublicKeyParameters publicKeyParameters;
    private String id;

    public RELSW10aSecretKeyGenerationParameters(CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters, String id) {
        super(null, REEngine.STENGTH);
        this.masterSecretKeyParameters = (RELSW10aMasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (RELSW10aPublicKeyParameters)publicKeyParameters;
        this.id = new String(id);
    }

    public RELSW10aMasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RELSW10aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() { return new String(this.id); }
}
