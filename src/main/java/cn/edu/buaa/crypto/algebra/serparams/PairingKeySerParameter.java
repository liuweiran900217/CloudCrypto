package cn.edu.buaa.crypto.algebra.serparams;

import it.unisa.dia.gas.jpbc.PairingParameters;

import java.io.Serializable;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Pairing-based scheme key serializable parameters.
 */
public class PairingKeySerParameter extends AsymmetricKeySerParameter implements Serializable {
    private PairingParameters parameters;

    public PairingKeySerParameter(boolean isPrivate, PairingParameters parameters) {
        super(isPrivate);
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
        if (anOjbect instanceof PairingKeySerParameter) {
            PairingKeySerParameter that = (PairingKeySerParameter)anOjbect;
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}