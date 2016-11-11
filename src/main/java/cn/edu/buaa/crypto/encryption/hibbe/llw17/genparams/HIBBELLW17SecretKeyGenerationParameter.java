package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE secret key generation parameter.
 */
public class HIBBELLW17SecretKeyGenerationParameter extends KeyGenerationParameters {
    private HIBBELLW17MasterSecretKeySerParameter masterSecretKeyParameters;
    private HIBBELLW17PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBBELLW17SecretKeyGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW17MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW17PublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
    }

    public HIBBELLW17MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW17PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}
