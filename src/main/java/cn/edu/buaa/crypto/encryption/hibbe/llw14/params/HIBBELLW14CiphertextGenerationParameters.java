package cn.edu.buaa.crypto.encryption.hibbe.llw14.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14CiphertextGenerationParameters implements CipherParameters {
    private HIBBELLW14PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW14CiphertextGenerationParameters(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBBELLW14PublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBBELLW14PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdAt(int index) { return ids[index]; }
}
