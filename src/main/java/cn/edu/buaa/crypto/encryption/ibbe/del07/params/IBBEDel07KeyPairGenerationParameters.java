package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Public key / master secret key parameter generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxBroadcastReceiver;
    private int rBitLength;
    private int qBitLength;

    public IBBEDel07KeyPairGenerationParameters(int rBitLength, int qBitLength, int maxBroadcastReceiver) {
        super(null, IBBEEngine.STENGTH);

        this.maxBroadcastReceiver = maxBroadcastReceiver;
        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxBroadcastReceiver() { return this.maxBroadcastReceiver; }
}
