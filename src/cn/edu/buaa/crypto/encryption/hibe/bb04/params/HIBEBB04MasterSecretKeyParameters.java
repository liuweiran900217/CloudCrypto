package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04MasterSecretKeyParameters extends PairingKeyParameters {

    private Element g2Alpha;

    public HIBEBB04MasterSecretKeyParameters(PairingParameters pairingParameters, Element g2Alpha) {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
    }

    public Element getG2Alpha(){
        return this.g2Alpha;
    }
}
