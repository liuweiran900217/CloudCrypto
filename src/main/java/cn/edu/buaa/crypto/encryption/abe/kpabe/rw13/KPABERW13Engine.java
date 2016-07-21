package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13;

import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * KP-ABE scheme proposed by Rouselakis and Waters in 2013.
 * Conference version: Rouselakis Y, Waters B. Practical constructions and new proof methods for large-universe attribute-based encryption.
 */
public class KPABERW13Engine extends KPABEEngine {
    public static final String SCHEME_NAME = "Rouselakis-Waters Key-Policy Attribute-Based Encryption";

    public KPABERW13Engine() {

    }

    @Override
    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength) {
        return null;
    }

    @Override
    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        return null;
    }

    @Override
    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String[] attributeSet) {
        return null;
    }

    @Override
    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey, String[] attributeSet, CipherParameters ciphertext) throws InvalidCipherTextException {
        return new byte[0];
    }
}
