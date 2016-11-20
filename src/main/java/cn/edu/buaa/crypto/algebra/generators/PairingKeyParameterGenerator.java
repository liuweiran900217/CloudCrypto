package cn.edu.buaa.crypto.algebra.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Pairing-based serializable key parameters generator
 */
public interface PairingKeyParameterGenerator {

    void init(KeyGenerationParameters keyGenerationParameters);

    PairingKeySerParameter generateKey();
}
