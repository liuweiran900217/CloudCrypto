package cn.edu.buaa.crypto.algebra.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.io.Serializable;

/**
 * Created by Weiran Liu on 15-10-2.
 *
 * Generic pairing key parameters.
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
