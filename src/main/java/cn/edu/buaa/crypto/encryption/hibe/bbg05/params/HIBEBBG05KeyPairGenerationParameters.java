package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Public Key / Master Secret Key generation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxDepth;
    private int rBitLength;
    private int qBitLength;

    public HIBEBBG05KeyPairGenerationParameters(int rBitLength, int qBitLength, int maxDepth) {
        super(null, PairingUtils.STENGTH);

        this.maxDepth = maxDepth;
        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxDepth() { return this.maxDepth; }
}
