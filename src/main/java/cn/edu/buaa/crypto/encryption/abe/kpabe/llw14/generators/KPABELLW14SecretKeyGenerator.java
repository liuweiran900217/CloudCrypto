package cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Liu-Liu-Wu CCA2-secure KP-ABE secret key generator.
 */
public class KPABELLW14SecretKeyGenerator extends KPABERW13SecretKeyGenerator {
    public void init(KeyGenerationParameters keyGenerationParameter) {
        KPABESecretKeyGenerationParameter oriParameter = (KPABESecretKeyGenerationParameter)keyGenerationParameter;
        String[] oriRhos = oriParameter.getRhos();
        Pairing pairing = PairingFactory.getPairing(oriParameter.getPublicKeyParameter().getParameters());
        Element[] mappedElementRhos = PairingUtils.MapStringArrayToFirstHalfZr(pairing, oriRhos);
        String[] mappedRhos = PairingUtils.MapElementArrayToStringArray(mappedElementRhos);
        KPABESecretKeyGenerationParameter parameter = new KPABESecretKeyGenerationParameter(
                oriParameter.getAccessControlEngine(),
                oriParameter.getPublicKeyParameter(),
                oriParameter.getMasterSecretKeyParameter(),
                oriParameter.getAccessPolicy(),
                mappedRhos
        );
        super.init(parameter);
    }

    public PairingKeySerParameter generateKey() {
        KPABERW13SecretKeySerParameter oriParameter = (KPABERW13SecretKeySerParameter) super.generateKey();
        return new KPABELLW14SecretKeySerParameter(
                oriParameter.getParameters(),
                oriParameter.getAccessControlParameter(),
                oriParameter.getK0s(),
                oriParameter.getK1s(),
                oriParameter.getK2s());
    }
}