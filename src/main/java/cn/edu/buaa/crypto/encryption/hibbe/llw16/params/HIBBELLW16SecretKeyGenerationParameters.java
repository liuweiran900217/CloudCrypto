package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Secret Key Generation parameters for Liu-Liu-Wu HIBBE published in 2016.
 */
public class HIBBELLW16SecretKeyGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW16MasterSecretKeyParameters masterSecretKeyParameters;
    private HIBBELLW16PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBBELLW16SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingUtils.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW16MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW16PublicKeyParameters)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBBELLW16MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW16PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return Arrays.copyOf(ids, ids.length);
    }
}