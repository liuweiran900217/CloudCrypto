package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14SecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE secret key delegation parameter.
 */
public class HIBBELLW14DelegateGenerationParameter extends PairingKeyDelegationParameter {
    private int index;
    private String delegateId;

    public HIBBELLW14DelegateGenerationParameter(PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter secretKeyParameter, int index, String id) {
        super(publicKeyParameter, secretKeyParameter);
        assert(((HIBBELLW14SecretKeySerParameter)secretKeyParameter).getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }
}
