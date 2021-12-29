package cn.edu.buaa.crypto.algebra.serparams;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 * 通用的基于配对的密钥封装密文/会话密钥封装对
 * Generic pairing-based key encapsulation ciphertext / session key encapsulation pair.
 */
public class PairingKeyEncapsulationSerPair implements CipherParameters {
    private byte[] sessionKey;
    private PairingCipherSerParameter header;

    /**
     * basic constructor.
     *
     * @param sessionKey a byte array session key.
     * @param ciphertextParam the corresponding ciphertext parameters.
     */
    public PairingKeyEncapsulationSerPair(byte[] sessionKey, PairingCipherSerParameter ciphertextParam) {
        this.sessionKey = sessionKey;
        this.header = ciphertextParam;
    }

    /**
     * return the session key parameters.
     *
     * @return the session key parameters
     */
    public byte[] getSessionKey() { return this.sessionKey; }

    /**
     * return the header parameters.
     *
     * @return the header parameters.
     */
    public PairingCipherSerParameter getHeader()
    {
        return this.header;
    }
}
