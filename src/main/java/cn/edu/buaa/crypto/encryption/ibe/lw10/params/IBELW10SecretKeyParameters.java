package cn.edu.buaa.crypto.encryption.ibe.lw10.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10SecretKeyParameters extends PairingKeyParameters {

    private final String id;
    private final Element elementId;

    private final Element k1;
    private final Element k2;


    public IBELW10SecretKeyParameters(PairingParameters pairingParameters, String id, Element elementId, Element k1, Element k2) {
        super(true, pairingParameters);

        this.k1 = k1.getImmutable();
        this.k2 = k2.getImmutable();
        this.id = id;
        this.elementId = elementId.getImmutable();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getK1() { return this.k1.duplicate(); }

    public Element getK2() { return this.k2.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof IBELW10SecretKeyParameters) {
            IBELW10SecretKeyParameters that = (IBELW10SecretKeyParameters)anOjbect;
            //Compare id
            if (!this.id.equals(that.getId())) {
                return false;
            }
            //Compare elementId
            if (!PairingUtils.isEqualElement(this.elementId, that.getElementId())) {
                return false;
            }
            //Compare k1
            if (!PairingUtils.isEqualElement(this.k1, that.getK1())) {
                return false;
            }
            //Compare k2
            if (!PairingUtils.isEqualElement(this.k2, that.getK2())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
