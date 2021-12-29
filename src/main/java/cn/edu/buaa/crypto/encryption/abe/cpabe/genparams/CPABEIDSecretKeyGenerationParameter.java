package cn.edu.buaa.crypto.encryption.abe.cpabe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

public class CPABEIDSecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String id;

    public CPABEIDSecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                           PairingKeySerParameter masterSecretKeyParameter, String id) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.id = id;
    }

    public String getId() {
        return this.id;
    }
}
