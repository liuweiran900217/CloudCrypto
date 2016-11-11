package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bSecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE secret key delegation generation parameter.
 */
public class HIBBELLW16bDelegateGenerationParameter  extends KeyGenerationParameters {
    private HIBBELLW16bPublicKeySerParameter publicKeyParameters;
    private HIBBELLW16bSecretKeySerParameter secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW16bDelegateGenerationParameter(CipherParameters publicKeyParameters, CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.publicKeyParameters = (HIBBELLW16bPublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16bSecretKeySerParameter)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW16bPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW16bSecretKeySerParameter getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }

}