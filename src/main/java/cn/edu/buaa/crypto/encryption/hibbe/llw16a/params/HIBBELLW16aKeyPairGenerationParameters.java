package cn.edu.buaa.crypto.encryption.hibbe.llw16a.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE public Key / master secret key generation parameters.
 */
public class HIBBELLW16aKeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxUser;
    private int rBitLength;
    private int qBitLength;

    public HIBBELLW16aKeyPairGenerationParameters(int rBitLength, int qBitLength, int maxUser) {
        super(null, PairingUtils.STENGTH);

        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
        this.maxUser = maxUser;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxUser() { return this.maxUser; }
}
