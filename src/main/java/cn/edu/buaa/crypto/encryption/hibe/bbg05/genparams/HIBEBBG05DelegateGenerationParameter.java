package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Delegation generation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05DelegateGenerationParameter extends PairingKeyDelegationParameter {
    private String delegateId;

    public HIBEBBG05DelegateGenerationParameter(PairingKeySerParameter publicKeyParameters,
            PairingKeySerParameter secretKeyParameters, String id) {
        super(publicKeyParameters, secretKeyParameters);
        this.delegateId = id;
    }

    public String getDelegateId() { return this.delegateId; }
}
