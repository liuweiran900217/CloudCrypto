package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE secret key generation parameter.
 */
public class HIBBELLW16bSecretKeyGenerationParameter  extends KeyGenerationParameters {
    private HIBBELLW16bMasterSecretKeySerParameter masterSecretKeyParameters;
    private HIBBELLW16bPublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBBELLW16bSecretKeyGenerationParameter(CipherParameters publicKeyParameters, CipherParameters masterSecretKeyParameters,
                                                   String[] ids) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW16bMasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW16bPublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
    }

    public HIBBELLW16bMasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW16bPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}