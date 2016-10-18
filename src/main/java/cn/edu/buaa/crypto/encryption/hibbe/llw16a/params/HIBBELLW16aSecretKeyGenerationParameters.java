package cn.edu.buaa.crypto.encryption.hibbe.llw16a.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE secret key generation parameters.
 */
public class HIBBELLW16aSecretKeyGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW16aMasterSecretKeyParameters masterSecretKeyParameters;
    private HIBBELLW16aPublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW16aSecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingUtils.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW16aMasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW16aPublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
    }

    public HIBBELLW16aMasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW16aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}