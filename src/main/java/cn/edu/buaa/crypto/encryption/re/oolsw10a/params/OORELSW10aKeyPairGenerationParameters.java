package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aKeyPairGenerationParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aKeyPairGenerationParameters extends KeyGenerationParameters {
    private int rBitLength;
    private int qBitLength;
    private CHEngine chEngine;

    public OORELSW10aKeyPairGenerationParameters(int rBitLength, int qBitLength, CHEngine chEngine) {
        super(null, OOREEngine.STENGTH);
        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
        this.chEngine = chEngine;
    }

    public CHEngine getCHEngine() {
        return this.chEngine;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }
}
