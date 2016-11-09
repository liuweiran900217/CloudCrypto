package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Public Key / Master Secret Key generation parameters for Rouselakis-Waters CP-ABE.
 */

public class CPABERW13KeyPairGenerationParameters extends KeyGenerationParameters {
    private AccessControlEngine accessControlEngine;
    private int rBitLength;
    private int qBitLength;

    public CPABERW13KeyPairGenerationParameters(int rBitLength, int qBitLength, AccessControlEngine accessControlEngine) {
        super(null, PairingParametersGenerationParameters.STENGTH);

        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
        this.accessControlEngine = accessControlEngine;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }
}