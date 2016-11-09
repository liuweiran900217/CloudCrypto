package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE secret key generation parameters.
 */
public class HIBBELLW16aSecretKeyGenerationParameter extends KeyGenerationParameters {
    private HIBBELLW16aMasterSecretKeySerParameter masterSecretKeyParameters;
    private HIBBELLW16aPublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBBELLW16aSecretKeyGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (HIBBELLW16aMasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
    }

    public HIBBELLW16aMasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBBELLW16aPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}