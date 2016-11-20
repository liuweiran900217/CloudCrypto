package cn.edu.buaa.crypto.algebra.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * interface that a pairing-based encryption generator should conform to.
 */
public interface PairingEncryptionGenerator {

    /**
     * intialise the encryption generator.
     *
     * @param params the parameters the public key pair is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * return the generated ciphertext.
     *
     * @return a PairingCipherSerParameter representing the ciphertext.
     */
    PairingCipherSerParameter generateCiphertext();
}
