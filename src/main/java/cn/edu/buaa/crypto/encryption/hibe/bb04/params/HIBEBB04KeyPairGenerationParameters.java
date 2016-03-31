package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxDepth;
    private int rBitLength;
    private int qBitLength;

    public HIBEBB04KeyPairGenerationParameters(int rBitLength, int qBitLength, int maxDepth) {
        super(null, HIBEBB04Engine.STENGTH);

        this.maxDepth = maxDepth;
        this.rBitLength = rBitLength;
        this.qBitLength = qBitLength;
    }

    public int getRBitLength() { return this.rBitLength; }

    public int getQBitLength() { return this.qBitLength; }

    public int getMaxDepth() { return this.maxDepth; }

}
