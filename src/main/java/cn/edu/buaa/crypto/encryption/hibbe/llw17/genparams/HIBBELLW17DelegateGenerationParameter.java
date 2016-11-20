package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17SecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE secret key delegation generation parameter.
 */
public class HIBBELLW17DelegateGenerationParameter extends PairingKeyDelegationParameter {
    private int index;
    private String delegateId;

    public HIBBELLW17DelegateGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter, int index, String id) {
        super(publicKeyParameter, secretKeyParameter);
        assert(((HIBBELLW17SecretKeySerParameter)secretKeyParameter).getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }
}
