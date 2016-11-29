package cn.edu.buaa.crypto.encryption.ibe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Identity-Based Encryption secret key generation parameter.
 */
public class IBESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String id;

    public IBESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                               PairingKeySerParameter masterSecretKeyParameter, String id) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

}