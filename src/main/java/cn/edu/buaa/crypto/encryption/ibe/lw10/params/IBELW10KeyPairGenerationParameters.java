package cn.edu.buaa.crypto.encryption.ibe.lw10.params;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */

public class IBELW10KeyPairGenerationParameters extends KeyGenerationParameters {
    private int qBitLength;

    public IBELW10KeyPairGenerationParameters(int qBitLength) {
        super(null, IBEEngine.STENGTH);

        this.qBitLength = qBitLength;
    }

    public int getQBitLength() { return this.qBitLength; }
}
