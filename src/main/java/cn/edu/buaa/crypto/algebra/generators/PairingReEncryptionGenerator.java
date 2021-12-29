package cn.edu.buaa.crypto.algebra.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by gccat on 21-12-27.
 * interface that a pairing-based re-encryption generator should conform to.
 */

public interface PairingReEncryptionGenerator {

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
    PairingCipherSerParameter generateCiphertext() throws InvalidCipherTextException;

}
