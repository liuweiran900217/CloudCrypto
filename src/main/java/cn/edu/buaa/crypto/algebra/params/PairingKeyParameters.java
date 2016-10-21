package cn.edu.buaa.crypto.algebra.params;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Created by Weiran Liu on 15-10-2.
 *
 * Generic pairing key parameters.
 */
public class PairingKeyParameters extends AsymmetricKeyParameter {
    private PairingParameters parameters;

    public PairingKeyParameters(boolean isPrivate, PairingParameters parameters) {
        super(isPrivate);
        this.parameters = parameters;
    }

    public PairingParameters getParameters() {
        return parameters;
    }
}
