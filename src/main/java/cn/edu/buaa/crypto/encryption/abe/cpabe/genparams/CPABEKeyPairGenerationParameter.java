package cn.edu.buaa.crypto.encryption.abe.cpabe.genparams;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * CP-ABE public key / master secret key pair generation parameter.
 */
public class CPABEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxAttributesNum;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;

    public CPABEKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
        this.maxAttributesNum = -1;
    }

    public CPABEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxAttributesNum) {
        super(pairingParameters);
        this.maxAttributesNum = maxAttributesNum;
    }

    public CPABEKeyPairGenerationParameter(PairingParameters pairingParameters,
                                           AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator) {
        super(pairingParameters);
        this.maxAttributesNum = -1;
        this.chameleonHashKeyPairGenerator = chameleonHashKeyPairGenerator;
    }

    public int getMaxAttributesNum() {
        return this.maxAttributesNum;
    }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }
}