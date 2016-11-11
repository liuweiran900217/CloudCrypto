package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE secret key delegation generation parameter.
 */
public class HIBBELLW17DelegateGenerationParameter extends KeyGenerationParameters {
    private HIBBELLW17PublicKeySerParameter publicKeyParameters;
    private HIBBELLW17SecretKeySerParameter secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW17DelegateGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.publicKeyParameters = (HIBBELLW17PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW17SecretKeySerParameter)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW17PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW17SecretKeySerParameter getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }
}
