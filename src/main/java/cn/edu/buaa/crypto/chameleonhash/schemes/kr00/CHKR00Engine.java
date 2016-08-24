package cn.edu.buaa.crypto.chameleonhash.schemes.kr00;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.chameleonhash.*;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.generators.CHKR00KeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00HashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00KeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00SecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashAsymmetricCipherKeyPair;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00Engine implements CHEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "KR00ChameleonHash";

    public String getName() {
        return SCHEME_NAME;
    }

    public ChameleonHashAsymmetricCipherKeyPair keyGen(int rBitLength, int qBitLength) {
        CHKR00KeyPairGenerator keyPairGenerator = new CHKR00KeyPairGenerator();
        keyPairGenerator.init(new CHKR00KeyGenerationParameters(cn.edu.buaa.crypto.algebra.PairingUtils.GenerateTypeAParameters(rBitLength, qBitLength)));
        return keyPairGenerator.generateKeyPair();
    }

    public ChameleonHashAsymmetricCipherKeyPair keyGen(PairingParameters pairingParameters) {
        CHKR00KeyPairGenerator keyPairGenerator = new CHKR00KeyPairGenerator();
        keyPairGenerator.init(new CHKR00KeyGenerationParameters(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message) {
        if (!(publicKeyParameter instanceof CHKR00PublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHKR00Engine.SCHEME_NAME + " Chameleon Hash, find "
                            + publicKeyParameter.getClass().getName() + ", require "
                            + CHKR00PublicKeyParameters.class.getName());
        }
        CHKR00PublicKeyParameters publicKey = (CHKR00PublicKeyParameters)publicKeyParameter;
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m = PairingUtils.MapToZr(pairing, message);
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element hashResult = publicKey.getG().powZn(m).mul(publicKey.getY().powZn(r)).getImmutable();
        return new CHKR00HashResultParameters(m, hashResult, r);
    }

    public ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message, Element... r) {
        if (!(publicKeyParameter instanceof CHKR00PublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHKR00Engine.SCHEME_NAME + " Chameleon Hash, find "
                            + publicKeyParameter.getClass().getName() + ", require "
                            + CHKR00PublicKeyParameters.class.getName());
        }
        CHKR00PublicKeyParameters publicKey = (CHKR00PublicKeyParameters)publicKeyParameter;
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m  = PairingUtils.MapToZr(pairing, message);
        Element hashResult = publicKey.getG().powZn(m).mul(publicKey.getY().powZn(r[0])).getImmutable();
        return new CHKR00HashResultParameters(m, hashResult, r);
    }

    public ChameleonHashResultParameters collision(ChameleonHashSecretKeyParameters secretKeyParameters, ChameleonHashResultParameters hash, byte[] anMessage) {
        if (!(secretKeyParameters instanceof CHKR00SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHKR00Engine.SCHEME_NAME + " Collision, find "
                            + secretKeyParameters.getClass().getName() + ", require "
                            + CHKR00SecretKeyParameters.class.getName());
        }
        CHKR00SecretKeyParameters secretKey = (CHKR00SecretKeyParameters)secretKeyParameters;
        CHKR00PublicKeyParameters publicKey = (CHKR00PublicKeyParameters)secretKey.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m = hash.getHashMessage();
        Element mPrime = PairingUtils.MapToZr(pairing, anMessage);
        Element[] r = hash.getRs();
        Element[] rPrime = new Element[] {r[0].add(secretKey.getX().invert().mul(m.sub(mPrime))).getImmutable()};
        return new CHKR00HashResultParameters(mPrime, hash.getHashResult(), rPrime);
    }
}
