package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.genparams.KPABEGPSW06bKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles public key / master secret key pair generator.
 */
public class KPABEGPSW06bKeyPairGenerator implements PairingKeyPairGenerator {
    private KPABEGPSW06bKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABEGPSW06bKeyPairGenerationParameter) keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element g1 = g.powZn(y).getImmutable();
        Element g2 = pairing.getG1().newRandomElement().getImmutable();

        return new PairingKeySerPair(
                new KPABEGPSW06bPublicKeySerParameter(this.parameters.getPairingParameters(), g, g1, g2),
                new KPABEGPSW06bMasterSecretKeySerParameter(this.parameters.getPairingParameters(), y));
    }
}