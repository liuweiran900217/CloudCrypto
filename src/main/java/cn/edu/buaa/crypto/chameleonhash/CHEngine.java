package cn.edu.buaa.crypto.chameleonhash;

import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashAsymmetricCipherKeyPair;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public interface CHEngine {
    //Default strengh, useless in pairing-based cryptography
    int STRENGTH = 12;

    public String getName();

    public ChameleonHashAsymmetricCipherKeyPair keyGen(int rBitLength, int qBitLength);

    public ChameleonHashAsymmetricCipherKeyPair keyGen(PairingParameters pairingParameters);

    public ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message);

    public ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message, Element... r);

    public ChameleonHashResultParameters collision(ChameleonHashSecretKeyParameters secretKeyParameters, ChameleonHashResultParameters hashParameters, byte[] anMessage);
}
