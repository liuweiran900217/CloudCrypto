package cn.edu.buaa.crypto.encryption.hibbe.llw14.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14DecapsulationParameters implements CipherParameters {
    private HIBBELLW14PublicKeyParameters publicKeyParameters;
    private HIBBELLW14SecretKeyParameters secretKeyParameters;
    private String[] ids;
    private HIBBELLW14CiphertextParameters ciphertextParameters;

    public HIBBELLW14DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBBELLW14PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW14SecretKeyParameters)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (HIBBELLW14CiphertextParameters)ciphertextParameters;
    }

    public HIBBELLW14PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW14SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW14CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}
