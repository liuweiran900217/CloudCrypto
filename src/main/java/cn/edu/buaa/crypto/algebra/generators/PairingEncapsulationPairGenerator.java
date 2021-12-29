package cn.edu.buaa.crypto.algebra.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 * interface that a pairing KEM encryption pair generator should conform to.
 */

public interface PairingEncapsulationPairGenerator {

    /**
     * intialise the KEM encryption pair generator.
     * 初始化KEY加密对生成器
     *
     * @param params the parameters the public key pair is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * return an PairingKeyEncapsulationSerPair containing the generated session key and the ciphertext.
     * 返回一个密钥封装对：(会话密钥，密文)
     *
     * @return an PairingKeyEncapsulationSerPair containing the generated session key and the ciphertext.
     */
    PairingKeyEncapsulationSerPair generateEncryptionPair();
}
