package cn.edu.buaa.crypto.algebra.genparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Generic pairing-based key encapsulation ciphertext / session key encapsulation pair.
 */
public class PairingKeyEncapsulationSerPair implements CipherParameters {
    private byte[] sessionKey;
    private PairingCipherSerParameter ciphertext;

    /**
     * basic constructor.
     *
     * @param sessionKey a byte array session key.
     * @param ciphertextParam the corresponding ciphertext parameters.
     */
    public PairingKeyEncapsulationSerPair(byte[] sessionKey, PairingCipherSerParameter ciphertextParam) {
        this.sessionKey = sessionKey;
        this.ciphertext = ciphertextParam;
    }

    /**
     * return the session key parameters.
     *
     * @return the session key parameters
     */
    public byte[] getSessionKey() { return this.sessionKey; }

    /**
     * return the ciphertext parameters.
     *
     * @return the ciphertext parameters.
     */
    public PairingCipherSerParameter getCiphertext()
    {
        return this.ciphertext;
    }
}
