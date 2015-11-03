package cn.edu.buaa.crypto.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/11/3.
 */
public class HIBEBBG05Engine implements HIBEEngine {
    // Default strength for KeyPairGenerator, useless in Pairing based cryptography
    public static final int STENGTH = 12;

    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "BBG05HIBE";

    @Override
    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxDepth) {
        return null;
    }

    @Override
    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String... ids) {
        return null;
    }

    @Override
    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, String id) {
        return null;
    }

    @Override
    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids) {
        return null;
    }

    @Override
    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey, String[] ids, CipherParameters ciphertext) throws InvalidCipherTextException {
        return new byte[0];
    }
}
