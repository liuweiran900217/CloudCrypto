package cn.edu.buaa.crypto.chameleonhash.czk04.generators;

import cn.edu.buaa.crypto.chameleonhash.czk04.params.CHCZK04KeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.czk04.params.CHCZK04PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.czk04.params.CHCZK04SecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.BigIntegers;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class CHCZK04KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private CHCZK04KeyGenerationParameters params;

    public void init(KeyGenerationParameters params) { this.params = (CHCZK04KeyGenerationParameters) params; }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PairingParameters pairingParameters = params.getParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        CHCZK04SecretKeyParameters secretKeyParameters = generateSecretKey(pairing);
        CHCZK04PublicKeyParameters publicKeyParameters = generatePublicKey(pairing, secretKeyParameters);
        secretKeyParameters.setPublicKey(publicKeyParameters);

        return new AsymmetricCipherKeyPair(publicKeyParameters, secretKeyParameters);
    }

    private CHCZK04SecretKeyParameters generateSecretKey(Pairing pairing){
        CHCZK04SecretKeyParameters secretKeyParameters = new CHCZK04SecretKeyParameters(params.getParameters(),
                pairing.getZr().newRandomElement().getImmutable());
        return secretKeyParameters;
    }

    private CHCZK04PublicKeyParameters generatePublicKey(Pairing pairing, CHCZK04SecretKeyParameters secretKeyParameters) {
        Element g = pairing.getGT().newRandomElement().getImmutable();
        Element y = g.powZn(secretKeyParameters.getX()).getImmutable();
        return new CHCZK04PublicKeyParameters(params.getParameters(), g, y);
    }
}
