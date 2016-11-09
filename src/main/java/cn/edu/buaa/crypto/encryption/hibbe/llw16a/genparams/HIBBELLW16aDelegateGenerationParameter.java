package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aSecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE secret key delegation parameters.
 */
public class HIBBELLW16aDelegateGenerationParameter extends KeyGenerationParameters {
    private HIBBELLW16aPublicKeySerParameter publicKeyParameters;
    private HIBBELLW16aSecretKeySerParameter secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW16aDelegateGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16aSecretKeySerParameter)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW16aPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW16aSecretKeySerParameter getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }

}