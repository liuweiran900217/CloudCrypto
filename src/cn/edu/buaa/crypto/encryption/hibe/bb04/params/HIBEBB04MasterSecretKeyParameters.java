package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.util.encoders.Hex;

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

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04MasterSecretKeyParameters) {
            HIBEBB04MasterSecretKeyParameters that = (HIBEBB04MasterSecretKeyParameters)anObject;
            if (!(Utils.isEqualElement(this.g2Alpha, that.getG2Alpha()))) {
                return false;
            }
            return true;
        }
        return false;
    }
}
