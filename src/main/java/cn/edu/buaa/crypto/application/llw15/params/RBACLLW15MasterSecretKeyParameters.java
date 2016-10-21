package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/18.
 */
public class RBACLLW15MasterSecretKeyParameters extends PairingKeyParameters {

    private final Element g2Alpha;

    public RBACLLW15MasterSecretKeyParameters(PairingParameters pairingParameters, Element g2Alpha) {
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
        if (anObject instanceof RBACLLW15MasterSecretKeyParameters) {
            RBACLLW15MasterSecretKeyParameters that = (RBACLLW15MasterSecretKeyParameters)anObject;
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