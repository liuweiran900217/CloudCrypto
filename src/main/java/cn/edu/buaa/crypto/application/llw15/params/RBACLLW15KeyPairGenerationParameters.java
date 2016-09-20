package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Public Key / Master Secret Key generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxRoleNumber;
    private int rBitLength;
    private int qBitLength;

    public RBACLLW15KeyPairGenerationParameters(int rBitLength, int qBitLength, int maxRoleNumber) {
        super(null, PairingUtils.STENGTH);

        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
        this.maxRoleNumber = maxRoleNumber;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxRoleNumber() { return this.maxRoleNumber; }
}

