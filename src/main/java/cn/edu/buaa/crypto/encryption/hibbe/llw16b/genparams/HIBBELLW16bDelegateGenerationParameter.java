package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bSecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE secret key delegation generation parameter.
 */
public class HIBBELLW16bDelegateGenerationParameter extends PairingKeyDelegationParameter {
    private int index;
    private String delegateId;

    public HIBBELLW16bDelegateGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
                                                  int index, String id) {
        super(publicKeyParameter, secretKeyParameter);
        assert(((HIBBELLW16bSecretKeySerParameter)secretKeyParameter).getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }

}