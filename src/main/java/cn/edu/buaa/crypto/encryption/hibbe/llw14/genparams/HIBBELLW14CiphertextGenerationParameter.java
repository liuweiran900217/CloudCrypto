package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE ciphertext / session key generation parameter.
 */
public class HIBBELLW14CiphertextGenerationParameter implements CipherParameters {
    private HIBBELLW14PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBBELLW14CiphertextGenerationParameter(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBBELLW14PublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
    }

    public HIBBELLW14PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }
}
