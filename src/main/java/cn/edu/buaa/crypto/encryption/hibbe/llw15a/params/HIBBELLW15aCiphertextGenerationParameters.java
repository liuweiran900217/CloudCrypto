package cn.edu.buaa.crypto.encryption.hibbe.llw15a.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aCiphertextGenerationParameters implements CipherParameters {
    private HIBBELLW15aPublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW15aCiphertextGenerationParameters(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBBELLW15aPublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBBELLW15aPublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdAt(int index) { return ids[index]; }
}
