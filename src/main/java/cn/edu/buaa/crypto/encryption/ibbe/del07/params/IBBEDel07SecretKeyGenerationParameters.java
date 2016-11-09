package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Secret key parameter generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07SecretKeyGenerationParameters extends KeyGenerationParameters {

    private IBBEDel07MasterSecretKeySerParameter masterSecretKeyParameters;
    private IBBEDel07PublicKeySerParameter publicKeyParameters;
    private String id;

    public IBBEDel07SecretKeyGenerationParameters(CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters, String id) {
        super(null, IBBEEngine.STENGTH);
        this.masterSecretKeyParameters = (IBBEDel07MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (IBBEDel07PublicKeySerParameter)publicKeyParameters;
        this.id = id;
    }

    public IBBEDel07MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public IBBEDel07PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() {
        return this.id;
    }

}

