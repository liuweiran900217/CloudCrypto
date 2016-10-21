package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Master Secret Key Paramaters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05MasterSecretKeyParameters extends PairingKeyParameters {
    private Element g2Alpha;

    public HIBEBBG05MasterSecretKeyParameters(PairingParameters pairingParameters, Element g2Alpha) {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
    }

    public Element getG2Alpha() {
        return this.g2Alpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBBG05MasterSecretKeyParameters) {
            HIBEBBG05MasterSecretKeyParameters that = (HIBEBBG05MasterSecretKeyParameters)anObject;
            if (!(PairingUtils.isEqualElement(this.g2Alpha, that.getG2Alpha()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
