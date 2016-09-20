package cn.edu.buaa.crypto.chameleonhash;

import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashAsymmetricCipherKeyPair;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Generic Chameleon Hash Engine.
 */
public interface CHEngine {
    String getName();

    ChameleonHashAsymmetricCipherKeyPair keyGen(int rBitLength, int qBitLength);

    ChameleonHashAsymmetricCipherKeyPair keyGen(PairingParameters pairingParameters);

    ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message);

    ChameleonHashResultParameters chameleonHash(ChameleonHashPublicKeyParameters publicKeyParameter, byte[] message, Element... r);

    ChameleonHashResultParameters collision(ChameleonHashSecretKeyParameters secretKeyParameters, ChameleonHashResultParameters hashParameters, byte[] anMessage);
}
