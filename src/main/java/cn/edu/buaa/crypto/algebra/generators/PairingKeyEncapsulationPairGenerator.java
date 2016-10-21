package cn.edu.buaa.crypto.algebra.generators;

import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 * interface that a pairing KEM encryption pair generator should conform to.
 */

public interface PairingKeyEncapsulationPairGenerator {

    /**
     * intialise the KEM encryption pair generator.
     *
     * @param params the parameters the public key pair is to be initialised with.
     */
    public void init(CipherParameters params);

    /**
     * return an PairingKeyEncapsulationPair containing the generated session key and the ciphertext.
     *
     * @return an PairingKeyEncapsulationPair containing the generated session key and the ciphertext.
     */
    public PairingKeyEncapsulationPair generateEncryptionPair();
}
