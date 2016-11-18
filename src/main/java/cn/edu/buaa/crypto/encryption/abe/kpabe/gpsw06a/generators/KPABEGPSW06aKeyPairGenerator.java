package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE public key / master secret key pair generator.
 */
public class KPABEGPSW06aKeyPairGenerator implements AsymmetricKeySerPairGenerator {
    private KPABEGPSW06aKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABEGPSW06aKeyPairGenerationParameter)keyGenerationParameters;
    }

    public AsymmetricKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Map<String, Element> ts = new HashMap<String, Element>();
        Map<String, Element> Ts = new HashMap<String, Element>();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element Y = pairing.pairing(g, g).powZn(y).getImmutable();
        for (int i = 0; i < this.parameters.getMaxAttributesNum(); i++) {
            String attribute = String.valueOf(i);
            Element t = pairing.getZr().newRandomElement().getImmutable();
            ts.put(attribute, t);
            Ts.put(attribute, g.powZn(t).getImmutable());
        }

        return new AsymmetricKeySerPair(
                new KPABEGPSW06aPublicKeySerParameter(this.parameters.getPairingParameters(), g, Ts, Y),
                new KPABEGPSW06aMasterSecretKeySerParameter(this.parameters.getPairingParameters(), ts, y));
    }
}
