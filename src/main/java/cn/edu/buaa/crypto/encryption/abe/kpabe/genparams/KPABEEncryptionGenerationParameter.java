package cn.edu.buaa.crypto.encryption.abe.kpabe.genparams;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * KP-ABE ciphertext generation parameter.
 */
public class KPABEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String[] attributes;
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
    private KeyGenerationParameters chameleonHashKeyPairGenerationParameter;
    private PairingCipherSerParameter intermediate;

    public KPABEEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] attributes, Element message) {
        super(publicKeyParameter, message);
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator keyPairGenerator) {
        this.chameleonHashKeyPairGenerator = keyPairGenerator;
    }

    public void setChameleonHashKeyPairGenerationParameter(KeyGenerationParameters keyGenerationParameters) {
        this.chameleonHashKeyPairGenerationParameter = keyGenerationParameters;
    }

    public void setIntermediate(PairingCipherSerParameter intermediate) {
        this.intermediate = intermediate;
    }

    public String[] getAttributes() { return this.attributes; }

    public ChameleonHasher getChameleonHasher() {
        return this.chameleonHasher;
    }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }

    public KeyGenerationParameters getChameleonHashKeyPairGenerationParameter() {
        return this.chameleonHashKeyPairGenerationParameter;
    }

    public boolean isIntermediateGeneration() {
        return (this.intermediate != null);
    }

    public PairingCipherSerParameter getIntermediate() {
        return this.intermediate;
    }
}
