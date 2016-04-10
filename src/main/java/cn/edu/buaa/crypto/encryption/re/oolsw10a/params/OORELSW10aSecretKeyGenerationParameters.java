package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/10.
 */
public class OORELSW10aSecretKeyGenerationParameters extends KeyGenerationParameters {
    private OORELSW10aMasterSecretKeyParameters masterSecretKeyParameters;
    private OORELSW10aPublicKeyParameters publicKeyParameters;
    private String id;

    public OORELSW10aSecretKeyGenerationParameters(CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters, String id) {
        super(null, OOREEngine.STENGTH);
        this.masterSecretKeyParameters = (OORELSW10aMasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (OORELSW10aPublicKeyParameters)publicKeyParameters;
        this.id = new String(id);
    }

    public OORELSW10aMasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public OORELSW10aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() { return new String(this.id); }
}
