package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aSecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE secret key delegation parameters.
 */
public class HIBBELLW16aDelegateGenerationParameter extends PairingKeyDelegationParameter {
    private int index;
    private String delegateId;

    public HIBBELLW16aDelegateGenerationParameter(
            PairingKeySerParameter publicKeyParameters,
            PairingKeySerParameter secretKeyParameters,
            int index, String id) {
        super(publicKeyParameters, secretKeyParameters);
        assert(((HIBBELLW16aSecretKeySerParameter)secretKeyParameters).getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }

}