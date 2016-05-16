package cn.edu.buaa.crypto.encryption.hibbe.llw15a.params;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aKeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxUser;
    private int qBitLength;

    public HIBBELLW15aKeyPairGenerationParameters(int qBitLength, int maxUser) {
        super(null, HIBBEEngine.STENGTH);

        this.qBitLength = qBitLength;
        this.maxUser = maxUser;
    }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxUser() { return this.maxUser; }
}
