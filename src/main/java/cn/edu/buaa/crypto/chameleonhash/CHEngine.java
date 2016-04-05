package cn.edu.buaa.crypto.chameleonhash;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public interface CHEngine {
    //Default strengh, useless in pairing-based cryptography
    int STRENGTH = 12;

    public AsymmetricCipherKeyPair keyGen(int rBitLength, int qBitLength);

    public AsymmetricCipherKeyPair keyGen(PairingParameters pairingParameters);

    public ChameleonHashParameters chameleonHash(AsymmetricKeyParameter publicKeyParameter, byte[] message);

    public ChameleonHashParameters chameleonHash(AsymmetricKeyParameter publicKeyParameter, byte[] message, Element... r);

    public ChameleonHashParameters collision(AsymmetricKeyParameter secretKeyParameters, ChameleonHashParameters hashParameters, byte[] anMessage);
}
