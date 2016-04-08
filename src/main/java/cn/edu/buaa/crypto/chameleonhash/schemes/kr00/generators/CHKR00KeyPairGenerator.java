package cn.edu.buaa.crypto.chameleonhash.schemes.kr00.generators;

import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashAsymmetricCipherKeyPair;
import cn.edu.buaa.crypto.chameleonhash.generators.ChameleonHashAsymmetricCipherKeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00KeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00SecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00KeyPairGenerator implements ChameleonHashAsymmetricCipherKeyPairGenerator {
    private CHKR00KeyGenerationParameters params;

    public void init(KeyGenerationParameters params) { this.params = (CHKR00KeyGenerationParameters) params; }

    public ChameleonHashAsymmetricCipherKeyPair generateKeyPair() {
        PairingParameters pairingParameters = params.getParameters();
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        CHKR00SecretKeyParameters secretKeyParameters = generateSecretKey(pairing);
        CHKR00PublicKeyParameters publicKeyParameters = generatePublicKey(pairing, secretKeyParameters);
        secretKeyParameters.setPublicKeyParameters(publicKeyParameters);

        return new ChameleonHashAsymmetricCipherKeyPair(publicKeyParameters, secretKeyParameters);
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
