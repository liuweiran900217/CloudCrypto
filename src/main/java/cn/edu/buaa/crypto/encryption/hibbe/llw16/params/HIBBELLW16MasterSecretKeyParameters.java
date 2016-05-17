package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16MasterSecretKeyParameters extends PairingKeyParameters {

    private final Element g2Alpha;

    public HIBBELLW16MasterSecretKeyParameters(PairingParameters pairingParameters, Element g2Alpha) {
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
        if (anObject instanceof HIBBELLW16MasterSecretKeyParameters) {
            HIBBELLW16MasterSecretKeyParameters that = (HIBBELLW16MasterSecretKeyParameters)anObject;
            //Compare g2Alpha
            if (!(Utils.isEqualElement(this.g2Alpha, that.getG2Alpha()))) {
                return false;
            }
            return true;
        }
        return false;
    }
}