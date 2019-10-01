package cn.edu.buaa.crypto.algebra.serparams;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Generic pairing-based ciphertext parameters.
 */
public class PairingCipherSerParameter implements CipherParameters, Serializable {

    private PairingParameters parameters;

    public PairingCipherSerParameter(PairingParameters parameters) {
        this.parameters = parameters;
    }

    public PairingParameters getParameters() {
        return parameters;
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof PairingCipherSerParameter) {
            PairingCipherSerParameter that = (PairingCipherSerParameter)anOjbect;
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
