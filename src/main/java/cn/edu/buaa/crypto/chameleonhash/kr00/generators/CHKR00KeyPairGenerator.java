package cn.edu.buaa.crypto.chameleonhash.kr00.generators;

import cn.edu.buaa.crypto.chameleonhash.kr00.params.CHKR00KeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00.params.CHKR00PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00.params.CHKR00SecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private CHKR00KeyGenerationParameters params;

    public void init(KeyGenerationParameters params) { this.params = (CHKR00KeyGenerationParameters) params; }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PairingParameters pairingParameters = params.getParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        CHKR00SecretKeyParameters secretKeyParameters = generateSecretKey(pairing);
        CHKR00PublicKeyParameters publicKeyParameters = generatePublicKey(pairing, secretKeyParameters);
        secretKeyParameters.setPublicKey(publicKeyParameters);

        return new AsymmetricCipherKeyPair(publicKeyParameters, secretKeyParameters);
    }

    private CHKR00SecretKeyParameters generateSecretKey(Pairing pairing){
        CHKR00SecretKeyParameters secretKeyParameters = new CHKR00SecretKeyParameters(params.getParameters(),
                pairing.getZr().newRandomElement().getImmutable());
        return secretKeyParameters;
    }

    private CHKR00PublicKeyParameters generatePublicKey(Pairing pairing, CHKR00SecretKeyParameters secretKeyParameters) {
        Element g = pairing.getGT().newRandomElement().getImmutable();
        Element y = g.powZn(secretKeyParameters.getX()).getImmutable();
        return new CHKR00PublicKeyParameters(params.getParameters(), g, y);
    }
}
