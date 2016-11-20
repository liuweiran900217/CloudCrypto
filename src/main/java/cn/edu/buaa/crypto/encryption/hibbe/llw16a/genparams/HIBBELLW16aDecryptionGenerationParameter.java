package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aSecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE decryption generation parameters.
 */
public class HIBBELLW16aDecryptionGenerationParameter implements CipherParameters {
    private HIBBELLW16aPublicKeySerParameter publicKeyParameters;
    private HIBBELLW16aSecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private HIBBELLW16aCipherSerParameter ciphertextParameters;

    public HIBBELLW16aDecryptionGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16aSecretKeySerParameter)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
        this.ciphertextParameters = (HIBBELLW16aCipherSerParameter)ciphertextParameters;
    }

    public HIBBELLW16aPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW16aSecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW16aCipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}
