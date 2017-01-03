package cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators.KPABEHW14SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE secret key generator.
 */
public class KPABELLW16SecretKeyGenerator extends KPABEHW14SecretKeyGenerator {
    public void init(KeyGenerationParameters keyGenerationParameter) {
        KPABESecretKeyGenerationParameter oriParameter = (KPABESecretKeyGenerationParameter)keyGenerationParameter;
        String[] rhos = oriParameter.getRhos();
        Pairing pairing = PairingFactory.getPairing(oriParameter.getPublicKeyParameter().getParameters());
        Element[] mappedElementRhos = PairingUtils.MapStringArrayToFirstHalfZr(pairing, rhos);
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
        KPABEHW14SecretKeySerParameter oriParameter = (KPABEHW14SecretKeySerParameter) super.generateKey();
        return new KPABELLW16SecretKeySerParameter(
                oriParameter.getParameters(),
                oriParameter.getAccessControlParameter(),
                oriParameter.getK0s(),
                oriParameter.getK1s(),
                oriParameter.getK2s());
    }
}
