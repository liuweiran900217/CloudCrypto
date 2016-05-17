package cn.edu.buaa.crypto.encryption.hibbe.llw14.params;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14SecretKeyGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW14MasterSecretKeyParameters masterSecretKeyParameters;
    private HIBBELLW14PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW14SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, HIBBEEngine.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW14MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW14PublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBBELLW14MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW14PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return Arrays.copyOf(ids, ids.length);
    }
}
