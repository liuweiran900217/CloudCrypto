package cn.edu.buaa.crypto.encryption.ibe.LW10.params;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/6.
 */
public class IBELW10SecretKeyGenerationParameters extends KeyGenerationParameters {

    private IBELW10MasterSecretKeyParameters masterSecretKeyParameters;
    private IBELW10PublicKeyParameters publicKeyParameters;
    private String id;

    public IBELW10SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String id) {
        super(null, IBEEngine.STENGTH);
        this.masterSecretKeyParameters = (IBELW10MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (IBELW10PublicKeyParameters)publicKeyParameters;
        this.id = id;
    }

    public IBELW10MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public IBELW10PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() {
        return this.id;
    }

}
