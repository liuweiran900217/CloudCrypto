package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE secret key delegation parameter.
 */
public class HIBBELLW14DelegateGenerationParameter extends KeyGenerationParameters {
    private HIBBELLW14PublicKeySerParameter publicKeyParameters;
    private HIBBELLW14SecretKeySerParameter secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW14DelegateGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.publicKeyParameters = (HIBBELLW14PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW14SecretKeySerParameter)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW14PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW14SecretKeySerParameter getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }
}
