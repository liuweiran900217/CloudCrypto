package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE secret key generator.
 */
public class CPABELLW14SecretKeyGenerator extends CPABERW13SecretKeyGenerator {
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
        CPABERW13SecretKeySerParameter oriParameter = (CPABERW13SecretKeySerParameter) super.generateKey();
        return new CPABELLW14SecretKeySerParameter(
                oriParameter.getParameters(),
                oriParameter.getK0(),
                oriParameter.getK1(),
                oriParameter.getK2s(),
                oriParameter.getK3s());
    }
}
