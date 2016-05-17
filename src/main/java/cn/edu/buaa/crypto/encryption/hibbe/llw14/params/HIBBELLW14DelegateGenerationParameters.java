package cn.edu.buaa.crypto.encryption.hibbe.llw14.params;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14DelegateGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW14PublicKeyParameters publicKeyParameters;
    private HIBBELLW14SecretKeyParameters secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW14DelegateGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, HIBBEEngine.STENGTH);
        this.publicKeyParameters = (HIBBELLW14PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW14SecretKeyParameters)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW14PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW14SecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }
}
