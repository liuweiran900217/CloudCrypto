package cn.edu.buaa.crypto.encryption.hibe.bb04.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * Delegation generation parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04DelegateGenerationParameter extends PairingKeyDelegationParameter {
    private String delegateId;

    public HIBEBB04DelegateGenerationParameter(PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter secretKeyParameter, String id) {
        super(publicKeyParameter, secretKeyParameter);
        this.delegateId = id;
    }

    public String getDelegateId() { return this.delegateId; }
}
