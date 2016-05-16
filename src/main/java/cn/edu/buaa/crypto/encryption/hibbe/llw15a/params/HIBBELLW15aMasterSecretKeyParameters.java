package cn.edu.buaa.crypto.encryption.hibbe.llw15a.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aMasterSecretKeyParameters extends PairingKeyParameters {

    private final Element gAlpha;

    public HIBBELLW15aMasterSecretKeyParameters(PairingParameters pairingParameters, Element gAlpha) {
        super(true, pairingParameters);
        this.gAlpha = gAlpha.getImmutable();
    }

    public Element getGAlpha(){
        return this.gAlpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW15aMasterSecretKeyParameters) {
            HIBBELLW15aMasterSecretKeyParameters that = (HIBBELLW15aMasterSecretKeyParameters)anObject;
            //Compare gAlpha
            if (!(Utils.isEqualElement(this.gAlpha, that.getGAlpha()))) {
                return false;
            }
            return true;
        }
        return false;
    }
}
