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

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE public key / master secret key pair generator.
 */
public class KPABEGPSW06aKeyPairGenerator  implements AsymmetricKeySerPairGenerator {
    private KPABEGPSW06aKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABEGPSW06aKeyPairGenerationParameter)keyGenerationParameters;
    }

    public AsymmetricKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());
        Element[] ts = new Element[this.parameters.getMaxAttributesNum()];
        Element[] Ts = new Element[this.parameters.getMaxAttributesNum()];
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element Y = pairing.pairing(g, g).powZn(y).getImmutable();
        for (int i = 0; i < ts.length; i++) {
            ts[i] = pairing.getZr().newRandomElement().getImmutable();
            Ts[i] = g.powZn(ts[i]).getImmutable();
        }

        return new AsymmetricKeySerPair(
                new KPABEGPSW06aPublicKeySerParameter(this.parameters.getPairingParameters(), g, Ts, Y),
                new KPABEGPSW06aMasterSecretKeySerParameter(this.parameters.getPairingParameters(), ts, y));
    }
}
