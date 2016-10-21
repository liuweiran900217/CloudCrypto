package cn.edu.buaa.crypto.algebra.params;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Generic pairing-based ciphertext parameters.
 */
public class PairingCiphertextParameters implements CipherParameters {

    private PairingParameters parameters;

    public PairingCiphertextParameters(PairingParameters parameters) {
        this.parameters = parameters;
    }

    public PairingParameters getParameters() {
        return parameters;
    }
}
