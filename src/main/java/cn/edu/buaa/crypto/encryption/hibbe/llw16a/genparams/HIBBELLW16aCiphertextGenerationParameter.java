package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE ciphertext generation parameters.
 */
public class HIBBELLW16aCiphertextGenerationParameter implements CipherParameters {
    private HIBBELLW16aPublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBBELLW16aCiphertextGenerationParameter(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, ids.length);
    }

    public HIBBELLW16aPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }
}
