package cn.edu.buaa.crypto.signature.pks;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/17.
 *
 * Boneh-Boyen signature public key / secret key pair generation parameters.
 */
public class PairingSignKeyPairGenerationParameters extends KeyGenerationParameters {
    private int rBitLength;
    private int qBitLength;

    public PairingSignKeyPairGenerationParameters(int rBitLength, int qBitLength) {
        super(null, PairingUtils.STENGTH);

        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
    }

    public int getQBitLength() {
        return this.qBitLength;
    }

    public int getRBitLength() {
        return this.rBitLength;
    }
}