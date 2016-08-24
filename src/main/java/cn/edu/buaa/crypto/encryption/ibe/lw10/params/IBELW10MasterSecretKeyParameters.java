package cn.edu.buaa.crypto.encryption.ibe.lw10.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10MasterSecretKeyParameters extends PairingKeyParameters {

    private final Element alpha;
    private final Element g3Generator;

    public IBELW10MasterSecretKeyParameters(PairingParameters pairingParameters, Element alpha, Element g3Generator) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.g3Generator = g3Generator.getImmutable();
    }

    public Element getAlpha(){
        return this.alpha.duplicate();
    }

    public Element getG3Generator() { return this.g3Generator.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBELW10MasterSecretKeyParameters) {
            IBELW10MasterSecretKeyParameters that = (IBELW10MasterSecretKeyParameters)anObject;
            //Compare alpha
            if (!(PairingUtils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            //Compare g3Generator
            if (!(PairingUtils.isEqualElement(this.g3Generator, that.getG3Generator()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
