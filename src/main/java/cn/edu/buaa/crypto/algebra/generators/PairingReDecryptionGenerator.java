package cn.edu.buaa.crypto.algebra.generators;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

public interface PairingReDecryptionGenerator {

    /**
     * intialise the pairing-based decryption generator.
     *
     * @param params the parameters the decryption is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * return the message recovered from the ciphertext.
     *
     * @return the message recovered from the ciphertext.
     */
    Element recoverMessage() throws InvalidCipherTextException;
}
