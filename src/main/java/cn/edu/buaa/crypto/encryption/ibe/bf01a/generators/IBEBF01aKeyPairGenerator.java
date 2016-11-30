package cn.edu.buaa.crypto.encryption.ibe.bf01a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE public key / master secret key pair generator.
 */
public class IBEBF01aKeyPairGenerator implements PairingKeyPairGenerator {
    private IBEKeyPairGenerationParameter params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (IBEKeyPairGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.params.getPairingParameters());
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element gs = g.powZn(s).getImmutable();

        return new PairingKeySerPair(
                new IBEBF01aPublicKeySerParameter(this.params.getPairingParameters(), g, gs),
                new IBEBF01aMasterSecretKeySerParameter(this.params.getPairingParameters(), s));
    }
}
