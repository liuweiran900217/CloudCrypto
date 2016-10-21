package cn.edu.buaa.crypto.encryption.hibbe.llw16a.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE master secret key parameters.
 */
public class HIBBELLW16aMasterSecretKeyParameters extends PairingKeyParameters {

    private final Element g2Alpha;

    public HIBBELLW16aMasterSecretKeyParameters(PairingParameters pairingParameters, Element g2Alpha) {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
    }

    public Element getG2Alpha(){
        return this.g2Alpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16aMasterSecretKeyParameters) {
            HIBBELLW16aMasterSecretKeyParameters that = (HIBBELLW16aMasterSecretKeyParameters)anObject;
            //Compare g2Alpha
            if (!(PairingUtils.isEqualElement(this.g2Alpha, that.getG2Alpha()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}