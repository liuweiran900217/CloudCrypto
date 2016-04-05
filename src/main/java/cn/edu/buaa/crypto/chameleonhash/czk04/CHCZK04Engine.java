package cn.edu.buaa.crypto.chameleonhash.czk04;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHashParameters;
import cn.edu.buaa.crypto.chameleonhash.czk04.generators.CHCZK04KeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.czk04.params.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

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

    public AsymmetricCipherKeyPair keyGen(int rBitLength, int qBitLength) {
        CHCZK04KeyPairGenerator keyPairGenerator = new CHCZK04KeyPairGenerator();
        keyPairGenerator.init(new CHCZK04KeyGenerationParameters(Utils.GeneratePropertiesParameters(rBitLength, qBitLength)));
        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricCipherKeyPair keyGen(PairingParameters pairingParameters) {
        CHCZK04KeyPairGenerator keyPairGenerator = new CHCZK04KeyPairGenerator();
        keyPairGenerator.init(new CHCZK04KeyGenerationParameters(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public ChameleonHashParameters chameleonHash(AsymmetricKeyParameter publicKeyParameter, byte[] message) {
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
        return new ChameleonHashParameters(m, hashResult, r);
    }

    public ChameleonHashParameters chameleonHash(AsymmetricKeyParameter publicKeyParameter, byte[] message, Element[] r) {
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
        return new ChameleonHashParameters(m, hashResult, r);
    }

    public ChameleonHashParameters collision(AsymmetricKeyParameter secretKeyParameters, ChameleonHashParameters hash, byte[] anMessage) {
        if (!(secretKeyParameters instanceof CHCZK04SecretKeyParameters)) {
            throw new IllegalArgumentException
                    ("Invalid AsymmetricKeyParameter for " + CHCZK04Engine.SCHEME_NAME + " Collision, find "
                            + secretKeyParameters.getClass().getName() + ", require "
                            + CHCZK04SecretKeyParameters.class.getName());
        }
        CHCZK04SecretKeyParameters secretKey = (CHCZK04SecretKeyParameters)secretKeyParameters;
        Pairing pairing = PairingFactory.getPairing(secretKey.getPublicKey().getParameters());
        Element m = hash.getHashMessage();
        Element mPrime = Utils.MapToZr(pairing, anMessage);
        Element[] r = hash.getR();
        Element[] rPrime = new Element[] {
                secretKey.getPublicKey().getG().mul(r[2]).powZn(secretKey.getX().invert().mulZn(m.sub(mPrime))).mul(r[0]),
                r[1].mul(secretKey.getPublicKey().getG().mul(r[2]).powZn(m.sub(mPrime))), r[2]};
        return new ChameleonHashParameters(mPrime, hash.getHashResult(), rPrime);
    }
}
