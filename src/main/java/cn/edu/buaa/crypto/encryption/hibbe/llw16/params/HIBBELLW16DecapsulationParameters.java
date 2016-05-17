package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16DecapsulationParameters implements CipherParameters {
    private HIBBELLW16PublicKeyParameters publicKeyParameters;
    private HIBBELLW16SecretKeyParameters secretKeyParameters;
    private String[] ids;
    private HIBBELLW16CiphertextParameters ciphertextParameters;

    public HIBBELLW16DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBBELLW16PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16SecretKeyParameters)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (HIBBELLW16CiphertextParameters)ciphertextParameters;
    }

    public HIBBELLW16PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW16SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW16CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}
