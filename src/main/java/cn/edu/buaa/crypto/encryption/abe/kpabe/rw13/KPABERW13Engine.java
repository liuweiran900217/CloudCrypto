package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import it.unisa.dia.gas.jpbc.PairingParameters;
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

    public String getEngineName() {
        return null;
    }

    @Override
    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        return null;
    }

    @Override
    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                            int[][] accessPolicyIntArrays, String[] rhos) {
        return null;
    }

    @Override
    public PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String[] attributeSet) {
        return null;
    }

    @Override
    public byte[] decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey,
                                String[] attributeSet, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        return new byte[0];
    }
}
