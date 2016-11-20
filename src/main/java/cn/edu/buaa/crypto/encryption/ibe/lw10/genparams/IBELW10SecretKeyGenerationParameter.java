package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE secret key generation parameter.
 */
public class IBELW10SecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String id;

    public IBELW10SecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter masterSecretKeyParameter, String id) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

}
