package cn.edu.buaa.crypto.encryption.hibbe.llw16a.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE session key decapsulation parameters.
 */
public class HIBBELLW16aDecapsulationParameters implements CipherParameters {
    private HIBBELLW16aPublicKeyParameters publicKeyParameters;
    private HIBBELLW16aSecretKeyParameters secretKeyParameters;
    private String[] ids;
    private HIBBELLW16aCiphertextParameters ciphertextParameters;

    public HIBBELLW16aDecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBBELLW16aPublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16aSecretKeyParameters)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
        this.ciphertextParameters = (HIBBELLW16aCiphertextParameters)ciphertextParameters;
    }

    public HIBBELLW16aPublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW16aSecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW16aCiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}
