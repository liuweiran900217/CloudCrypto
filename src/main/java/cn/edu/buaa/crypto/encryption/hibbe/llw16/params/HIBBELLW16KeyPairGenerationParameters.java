package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Public Key / Master Secret Key generation parameters for Liu-Liu-Wu HIBBE published in 2016.
 */
public class HIBBELLW16KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxUser;
    private int rBitLength;
    private int qBitLength;

    public HIBBELLW16KeyPairGenerationParameters(int rBitLength, int qBitLength, int maxUser) {
        super(null, PairingUtils.STENGTH);

        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
        this.maxUser = maxUser;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxUser() { return this.maxUser; }
}
