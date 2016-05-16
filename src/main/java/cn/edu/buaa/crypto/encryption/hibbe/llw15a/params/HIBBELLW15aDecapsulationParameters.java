package cn.edu.buaa.crypto.encryption.hibbe.llw15a.params;

import cn.edu.buaa.crypto.encryption.hibbe.llw15a.HIBBELLW15aEngine;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aDecapsulationParameters implements CipherParameters {
    private HIBBELLW15aPublicKeyParameters publicKeyParameters;
    private HIBBELLW15aSecretKeyParameters secretKeyParameters;
    private String[] ids;
    private HIBBELLW15aCiphertextParameters ciphertextParameters;

    public HIBBELLW15aDecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBBELLW15aPublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW15aSecretKeyParameters)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (HIBBELLW15aCiphertextParameters)ciphertextParameters;
    }

    public HIBBELLW15aPublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW15aSecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW15aCiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}
