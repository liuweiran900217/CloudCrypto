package cn.edu.buaa.crypto.encryption.ibe.LW10.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 */
public class IBELW10CiphertextGenerationParameters implements CipherParameters {
    private IBELW10PublicKeyParameters publicKeyParameters;
    private String id;

    public IBELW10CiphertextGenerationParameters(CipherParameters publicKeyParameters, String id) {
        this.publicKeyParameters = (IBELW10PublicKeyParameters)publicKeyParameters;
        this.id = id;
    }

    public IBELW10PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String getId() { return this.id; }

}
