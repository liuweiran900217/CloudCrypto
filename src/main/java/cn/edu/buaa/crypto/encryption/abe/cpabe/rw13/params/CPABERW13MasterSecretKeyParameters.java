package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/9/19.
 *
 * Master Secret Key Parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13MasterSecretKeyParameters extends PairingKeyParameters {
    private final Element alpha;

    public CPABERW13MasterSecretKeyParameters(PairingParameters pairingParameters, Element alpha) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
    }

    public Element getAlpha() { return this.alpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13MasterSecretKeyParameters) {
            CPABERW13MasterSecretKeyParameters that = (CPABERW13MasterSecretKeyParameters)anObject;
            if (!(PairingUtils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
