package cn.edu.buaa.crypto.encryption.hibbe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14SecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE secret key delegation parameter.
 */
public class HIBBEDelegateGenerationParameter extends PairingKeyDelegationParameter {
    private int index;
    private String delegateId;

    public HIBBEDelegateGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                            PairingKeySerParameter secretKeyParameter, int index, String id) {
        super(publicKeyParameter, secretKeyParameter);
        this.index = index;
        this.delegateId = id;
    }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }
}
