package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/8/23.
 *
 * Master Secret Key Parameters for Delerablée IBBE
 */
public class IBBEMasterSecretKeyParameters extends PairingKeyParameters {

    private final Element g;
    private final Element gamma;

    public IBBEMasterSecretKeyParameters(PairingParameters pairingParameters, Element g, Element gamma) {
        super(true, pairingParameters);
        this.g = g.getImmutable();
        this.gamma = gamma.getImmutable();
    }

    public Element getG(){
        return this.g.duplicate();
    }

    public Element getGamma() { return this.gamma.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBBEMasterSecretKeyParameters) {
            IBBEMasterSecretKeyParameters that = (IBBEMasterSecretKeyParameters)anObject;
            //compare g
            if (!(Utils.isEqualElement(this.g, that.getG()))) {
                return false;
            }
            //compare gamma
            if (!(Utils.isEqualElement(this.gamma, that.getGamma()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
