package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16CiphertextGenerationParameters implements CipherParameters {
    private HIBBELLW16PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW16CiphertextGenerationParameters(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBBELLW16PublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBBELLW16PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdAt(int index) { return ids[index]; }
}
