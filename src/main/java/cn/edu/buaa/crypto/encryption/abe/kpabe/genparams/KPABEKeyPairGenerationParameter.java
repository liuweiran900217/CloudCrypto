package cn.edu.buaa.crypto.encryption.abe.kpabe.genparams;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * KP-ABE public key / master secret key pair generation parameter.
 */
public class KPABEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxAttributesNum;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
    private KeyGenerationParameters chameleonHashKeyGenerationParameter;

    public KPABEKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
        this.maxAttributesNum = -1;
    }

    public KPABEKeyPairGenerationParameter(
            PairingParameters pairingParameters,
            AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator,
            KeyGenerationParameters chameleonHashKeyGenerationParameter) {
        super(pairingParameters);
        this.maxAttributesNum = -1;
        this.chameleonHashKeyPairGenerator = chameleonHashKeyPairGenerator;
        this.chameleonHashKeyGenerationParameter = chameleonHashKeyGenerationParameter;
    }

    public KPABEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxAttributesNum) {
        super(pairingParameters);
        this.maxAttributesNum = maxAttributesNum;
    }

    public int getMaxAttributesNum() { return this.maxAttributesNum; }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }

    public KeyGenerationParameters getChameleonHashKeyGenerationParameter() {
        return this.chameleonHashKeyGenerationParameter;
    }
}