package cn.edu.buaa.crypto.chameleonhash.schemes.czk04;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.*;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.generators.CHCZK04KeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params.*;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashAsymmetricCipherKeyPair;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Implementation of ``Chameleon Hashing Withough Key Exposure'', by Xiaofeng Chen, Fangguo Zhang, Kwangjo Kim in ISC 2004.
 * The fully secure scheme requires a customized identity J = H(ID_R || ID_S || ID_T).
 * The signer must use a different public key J for each transaction with different ID_T.
 * In our scheme, we replace J with a random Element in GT to keep consistency.
 */
public class CHCZK04Engine implements CHEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "CZK04ChameleonHash";

    public ChameleonHashAsymmetricCipherKeyPair keyGen(int rBitLength, int qBitLength) {
        CHCZK04KeyPairGenerator keyPairGenerator = new CHCZK04KeyPairGenerator();
        keyPairGenerator.init(new CHCZK04KeyGenerationParameters(Utils.GeneratePropertiesParameters(rBitLength, qBitLength)));
        return keyPairGenerator.generateKeyPair();
    }

    public ChameleonHashAsymmetricCipherKeyPair keyGen(PairingParameters pairingParameters) {
        CHCZK04KeyPairGenerator keyPairGenerator = new CHCZK04KeyPairGenerator();
        keyPairGenerator.init(new CHCZK04KeyGenerationParameters(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message) {
        if (!(publicKeyParameter instanceof CHCZK04PublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHCZK04Engine.SCHEME_NAME + " Chameleon Hash, find "
                            + publicKeyParameter.getClass().getName() + ", require "
                            + CHCZK04PublicKeyParameters.class.getName());
        }
        CHCZK04PublicKeyParameters publicKey = (CHCZK04PublicKeyParameters)publicKeyParameter;
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m = Utils.MapToZr(pairing, message);
        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element[] r = new Element[] {publicKey.getG().powZn(a), publicKey.getY().powZn(a), pairing.getGT().newRandomElement().getImmutable()};
        Element hashResult = publicKey.getG().mul(r[2]).powZn(m).mul(r[1]).getImmutable();
        return new CHCZK04HashResultParameters(m, hashResult, r);
    }

    public ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message, Element[] r) {
        if (!(publicKeyParameter instanceof CHCZK04PublicKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHCZK04Engine.SCHEME_NAME + " Chameleon Hash, find "
                            + publicKeyParameter.getClass().getName() + ", require "
                            + CHCZK04PublicKeyParameters.class.getName());
        }
        CHCZK04PublicKeyParameters publicKey = (CHCZK04PublicKeyParameters)publicKeyParameter;
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m  = Utils.MapToZr(pairing, message);
        Element hashResult = publicKey.getG().mul(r[2]).powZn(m).mul(r[1]).getImmutable();
        return new CHCZK04HashResultParameters(m, hashResult, r);
    }

    public ChameleonHashResultParameters collision(ChameleonHashSecretKeyParameters secretKeyParameters, ChameleonHashResultParameters hash, byte[] anMessage) {
        if (!(secretKeyParameters instanceof CHCZK04SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHCZK04Engine.SCHEME_NAME + " Collision, find "
                            + secretKeyParameters.getClass().getName() + ", require "
                            + CHCZK04SecretKeyParameters.class.getName());
        }
        CHCZK04SecretKeyParameters secretKey = (CHCZK04SecretKeyParameters)secretKeyParameters;
        CHCZK04PublicKeyParameters publicKey = (CHCZK04PublicKeyParameters)secretKeyParameters.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKey.getParameters());
        Element m = hash.getHashMessage();
        Element mPrime = Utils.MapToZr(pairing, anMessage);
        Element[] r = hash.getRs();
        Element[] rPrime = new Element[] {
                publicKey.getG().mul(r[2]).powZn(secretKey.getX().invert().mulZn(m.sub(mPrime))).mul(r[0]),
                r[1].mul(publicKey.getG().mul(r[2]).powZn(m.sub(mPrime))), r[2]};
        return new ChameleonHashResultParameters(mPrime, hash.getHashResult(), rPrime);
    }
}
