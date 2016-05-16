package cn.edu.buaa.crypto.encryption.hibbe.llw15a.params;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aDelegateGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW15aPublicKeyParameters publicKeyParameters;
    private HIBBELLW15aSecretKeyParameters secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW15aDelegateGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, HIBBEEngine.STENGTH);
        this.publicKeyParameters = (HIBBELLW15aPublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW15aSecretKeyParameters)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW15aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW15aSecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }
}
