package cn.edu.buaa.crypto.encryption.hibbe.llw15a.params;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aSecretKeyGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW15aMasterSecretKeyParameters masterSecretKeyParameters;
    private HIBBELLW15aPublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW15aSecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, HIBBEEngine.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW15aMasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW15aPublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBBELLW15aMasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW15aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return Arrays.copyOf(ids, ids.length);
    }
}
