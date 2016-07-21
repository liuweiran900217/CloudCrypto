package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Master Secret Key Parameters for Rouselakis-Waters KP-ABE
 */
public class KPABERW13MasterSecretKeyParameters extends PairingKeyParameters {
    private final Element alpha;

    public KPABERW13MasterSecretKeyParameters(PairingParameters pairingParameters, Element alpha) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
    }

    public Element getAlpha() {
        return this.alpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABERW13MasterSecretKeyParameters) {
            KPABERW13MasterSecretKeyParameters that = (KPABERW13MasterSecretKeyParameters)anObject;
            //Compare alpha
            if (!(Utils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
