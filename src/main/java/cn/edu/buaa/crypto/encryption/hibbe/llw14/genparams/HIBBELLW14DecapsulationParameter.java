package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE session key decapsulation parameter.
 */
public class HIBBELLW14DecapsulationParameter implements CipherParameters {
    private HIBBELLW14PublicKeySerParameter publicKeyParameters;
    private HIBBELLW14SecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private HIBBELLW14CipherSerParameter ciphertextParameters;

    public HIBBELLW14DecapsulationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBBELLW14PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW14SecretKeySerParameter)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
        this.ciphertextParameters = (HIBBELLW14CipherSerParameter)ciphertextParameters;
    }

    public HIBBELLW14PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW14SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW14CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}
