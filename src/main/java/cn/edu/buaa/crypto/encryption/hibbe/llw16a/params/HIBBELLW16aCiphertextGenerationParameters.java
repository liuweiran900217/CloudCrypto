package cn.edu.buaa.crypto.encryption.hibbe.llw16a.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE ciphertext generation parameters.
 */
public class HIBBELLW16aCiphertextGenerationParameters implements CipherParameters {
    private HIBBELLW16aPublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW16aCiphertextGenerationParameters(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBBELLW16aPublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, ids.length);
    }

    public HIBBELLW16aPublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }
}
