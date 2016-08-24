package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Secret key parameter generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07SecretKeyGenerationParameters extends KeyGenerationParameters {

    private IBBEDel07MasterSecretKeyParameters masterSecretKeyParameters;
    private IBBEDel07PublicKeyParameters publicKeyParameters;
    private String id;

    public IBBEDel07SecretKeyGenerationParameters(CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters, String id) {
        super(null, IBBEEngine.STENGTH);
        this.masterSecretKeyParameters = (IBBEDel07MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (IBBEDel07PublicKeyParameters)publicKeyParameters;
        this.id = id;
    }

    public IBBEDel07MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public IBBEDel07PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() {
        return this.id;
    }

}

