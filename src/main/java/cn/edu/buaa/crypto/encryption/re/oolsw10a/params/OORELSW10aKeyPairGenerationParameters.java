package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aKeyPairGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aKeyPairGenerationParameters extends RELSW10aKeyPairGenerationParameters {
    private CHEngine chEngine;

    public OORELSW10aKeyPairGenerationParameters(int rBitLength, int qBitLength, CHEngine chEngine) {
        super(rBitLength, qBitLength);
        this.chEngine = chEngine;
    }

    public CHEngine getCHEngine() {
        return this.chEngine;
    }
}
