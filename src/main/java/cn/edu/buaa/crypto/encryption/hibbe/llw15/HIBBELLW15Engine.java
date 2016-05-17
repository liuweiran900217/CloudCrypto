package cn.edu.buaa.crypto.encryption.hibbe.llw15;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/17.
 */
public class HIBBELLW15Engine implements HIBBEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "LLW15HIBBE";

    public HIBBELLW15Engine() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxUser) {
        return null;
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String[] ids) {
        return null;
    }

    public CipherParameters delegate(CipherParameters publicKey, CipherParameters secretKey, int index, String id) {
        return null;
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String[] ids) {
        return null;
    }

    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey, String[] ids, CipherParameters ciphertext) throws InvalidCipherTextException {
        return new byte[0];
    }
}
