package cn.edu.buaa.crypto.encryption.abe.cpabe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

public class CPABEReDecGenerationParameter extends PairingDecryptionGenerationParameter {
    public CPABEReDecGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                         PairingKeySerParameter secretKeyParameter,
                                         PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
    }
}
