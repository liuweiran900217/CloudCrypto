package cn.edu.buaa.crypto.pairingkem.params;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Created by Weiran Liu on 15-10-2.
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
