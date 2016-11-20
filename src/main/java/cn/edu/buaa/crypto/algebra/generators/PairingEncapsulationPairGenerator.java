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
     *
     * @param params the parameters the public key pair is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * return an PairingKeyEncapsulationSerPair containing the generated session key and the ciphertext.
     *
     * @return an PairingKeyEncapsulationSerPair containing the generated session key and the ciphertext.
     */
    PairingKeyEncapsulationSerPair generateEncryptionPair();
}
