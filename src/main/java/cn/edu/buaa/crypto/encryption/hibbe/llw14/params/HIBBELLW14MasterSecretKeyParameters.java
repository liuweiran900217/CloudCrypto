package cn.edu.buaa.crypto.encryption.hibbe.llw14.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14MasterSecretKeyParameters extends PairingKeyParameters {

    private final Element gAlpha;

    public HIBBELLW14MasterSecretKeyParameters(PairingParameters pairingParameters, Element gAlpha) {
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
        if (anObject instanceof HIBBELLW14MasterSecretKeyParameters) {
            HIBBELLW14MasterSecretKeyParameters that = (HIBBELLW14MasterSecretKeyParameters)anObject;
            //Compare gAlpha
            if (!(PairingUtils.isEqualElement(this.gAlpha, that.getGAlpha()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
