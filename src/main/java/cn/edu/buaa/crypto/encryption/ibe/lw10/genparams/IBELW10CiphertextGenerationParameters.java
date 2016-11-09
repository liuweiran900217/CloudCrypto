package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10CiphertextGenerationParameters implements CipherParameters {
    private IBELW10PublicKeySerParameter publicKeyParameters;
    private String id;

    public IBELW10CiphertextGenerationParameters(CipherParameters publicKeyParameters, String id) {
        this.publicKeyParameters = (IBELW10PublicKeySerParameter)publicKeyParameters;
        this.id = id;
    }

    public IBELW10PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String getId() { return this.id; }

}
