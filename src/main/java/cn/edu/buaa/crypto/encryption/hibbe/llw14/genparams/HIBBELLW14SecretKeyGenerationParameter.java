package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE secret key generation parameter.
 */
public class HIBBELLW14SecretKeyGenerationParameter extends KeyGenerationParameters {
    private HIBBELLW14MasterSecretKeySerParameter masterSecretKeyParameters;
    private HIBBELLW14PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBBELLW14SecretKeyGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW14MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW14PublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
    }

    public HIBBELLW14MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW14PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}
