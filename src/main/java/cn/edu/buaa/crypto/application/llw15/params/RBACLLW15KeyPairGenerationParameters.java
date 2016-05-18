package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/18.
 */
public class RBACLLW15KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxRoleNumber;
    private int rBitLength;
    private int qBitLength;

    public RBACLLW15KeyPairGenerationParameters(int rBitLength, int qBitLength, int maxRoleNumber) {
        super(null, RBACLLW15Engine.STENGTH);

        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
        this.maxRoleNumber = maxRoleNumber;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxRoleNumber() { return this.maxRoleNumber; }
}

