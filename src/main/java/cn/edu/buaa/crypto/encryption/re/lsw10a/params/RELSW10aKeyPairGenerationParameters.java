package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.REEngine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class RELSW10aKeyPairGenerationParameters extends KeyGenerationParameters {
    private int rBitLength;
    private int qBitLength;

    public RELSW10aKeyPairGenerationParameters(int rBitLength, int qBitLength) {
        super(null, REEngine.STENGTH);
        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }
}
