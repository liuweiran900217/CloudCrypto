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
}