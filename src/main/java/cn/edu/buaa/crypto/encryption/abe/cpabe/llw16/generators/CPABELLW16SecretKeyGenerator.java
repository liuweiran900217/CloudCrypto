package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators.CPABEHW14SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-CP-ABE secret key generator.
 */
public class CPABELLW16SecretKeyGenerator extends CPABEHW14SecretKeyGenerator {
    public void init(KeyGenerationParameters keyGenerationParameter) {
        CPABESecretKeyGenerationParameter oriParameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
        String[] oriAttributes = oriParameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(oriParameter.getPublicKeyParameter().getParameters());
        Element[] mappedElementAttributes = PairingUtils.MapStringArrayToFirstHalfZr(
                pairing, oriAttributes);
        String[] mappedAttributes = PairingUtils.MapElementArrayToStringArray(mappedElementAttributes);
        CPABESecretKeyGenerationParameter parameter = new CPABESecretKeyGenerationParameter(
                oriParameter.getPublicKeyParameter(),
                oriParameter.getMasterSecretKeyParameter(),
                mappedAttributes
        );
        super.init(parameter);
    }

    public PairingKeySerParameter generateKey() {
        CPABEHW14SecretKeySerParameter oriParameter = (CPABEHW14SecretKeySerParameter) super.generateKey();
        return new CPABELLW16SecretKeySerParameter(
                oriParameter.getParameters(),
                oriParameter.getK0(),
                oriParameter.getK1(),
                oriParameter.getK2s(),
                oriParameter.getK3s());
    }
}
