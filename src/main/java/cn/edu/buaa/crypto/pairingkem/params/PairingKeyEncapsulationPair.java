package cn.edu.buaa.crypto.pairingkem.params;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class PairingKeyEncapsulationPair {
    private byte[] sessionKey;
    private PairingCiphertextParameters ciphertext;

    /**
     * basic constructor.
     *
     * @param sessionKey a byte array session key.
     * @param ciphertextParam the corresponding ciphertext parameters.
     */
    public PairingKeyEncapsulationPair(byte[] sessionKey, PairingCiphertextParameters ciphertextParam) {
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
    public PairingCiphertextParameters getCiphertext()
    {
        return this.ciphertext;
    }
}
