package cn.edu.buaa.crypto.chameleonhash.kr00;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHashParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00.generators.CHKR00KeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.kr00.params.CHKR00KeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00.params.CHKR00PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00.params.CHKR00SecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00Engine implements CHEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "KR00ChameleonHash";

    public AsymmetricCipherKeyPair keyGen(int rBitLength, int qBitLength) {
        CHKR00KeyPairGenerator keyPairGenerator = new CHKR00KeyPairGenerator();
        keyPairGenerator.init(new CHKR00KeyGenerationParameters(Utils.GeneratePropertiesParameters(rBitLength, qBitLength)));
        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricCipherKeyPair keyGen(PairingParameters pairingParameters) {
        CHKR00KeyPairGenerator keyPairGenerator = new CHKR00KeyPairGenerator();
        keyPairGenerator.init(new CHKR00KeyGenerationParameters(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public ChameleonHashParameters chameleonHash(AsymmetricKeyParameter publicKeyParameter, byte[] message) {
        if (!(publicKeyParameter instanceof CHKR00PublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHKR00Engine.SCHEME_NAME + " Chameleon Hash, find "
                            + publicKeyParameter.getClass().getName() + ", require "
                            + CHKR00PublicKeyParameters.class.getName());
        }
        CHKR00PublicKeyParameters publicKey = (CHKR00PublicKeyParameters)publicKeyParameter;
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m = Utils.MapToZr(pairing, message);
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element hashResult = publicKey.getG().powZn(m).mul(publicKey.getY().powZn(r)).getImmutable();
        return new ChameleonHashParameters(m, hashResult, r);
    }

    public ChameleonHashParameters chameleonHash(AsymmetricKeyParameter publicKeyParameter, byte[] message, Element... r) {
        if (!(publicKeyParameter instanceof CHKR00PublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHKR00Engine.SCHEME_NAME + " Chameleon Hash, find "
                            + publicKeyParameter.getClass().getName() + ", require "
                            + CHKR00PublicKeyParameters.class.getName());
        }
        CHKR00PublicKeyParameters publicKey = (CHKR00PublicKeyParameters)publicKeyParameter;
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m  = Utils.MapToZr(pairing, message);
        Element hashResult = publicKey.getG().powZn(m).mul(publicKey.getY().powZn(r[0])).getImmutable();
        return new ChameleonHashParameters(m, hashResult, r);
    }

    public ChameleonHashParameters collision(AsymmetricKeyParameter secretKeyParameters, ChameleonHashParameters hash, byte[] anMessage) {
        if (!(secretKeyParameters instanceof CHKR00SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHKR00Engine.SCHEME_NAME + " Collision, find "
                            + secretKeyParameters.getClass().getName() + ", require "
                            + CHKR00SecretKeyParameters.class.getName());
        }
        CHKR00SecretKeyParameters secretKey = (CHKR00SecretKeyParameters)secretKeyParameters;
        Pairing pairing = PairingFactory.getPairing(secretKey.getPublicKey().getParameters());
        Element m = hash.getHashMessage();
        Element mPrime = Utils.MapToZr(pairing, anMessage);
        Element[] r = hash.getR();
        Element[] rPrime = new Element[] {r[0].add(secretKey.getX().invert().mul(m.sub(mPrime))).getImmutable()};
        return new ChameleonHashParameters(mPrime, hash.getHashResult(), rPrime);
    }
}
