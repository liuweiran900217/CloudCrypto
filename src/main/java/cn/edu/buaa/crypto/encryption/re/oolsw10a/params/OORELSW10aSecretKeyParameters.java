package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aSecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aSecretKeyParameters extends PairingKeyParameters {
    private final String id;
    private final Element elementId;

    private final Element d0;
    private final Element d1;
    private final Element d2;

    public OORELSW10aSecretKeyParameters(PairingParameters pairingParameters,
                                       String id, Element elementId, Element d0, Element d1, Element d2) {
        super(true, pairingParameters);
        this.id = id;
        this.elementId = elementId.getImmutable();
        this.d0 = d0.getImmutable();
        this.d1 = d1.getImmutable();
        this.d2 = d2.getImmutable();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getD0() { return this.d0.duplicate(); }

    public Element getD1() { return this.d1.duplicate(); }

    public Element getD2() { return this.d2.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof RELSW10aSecretKeyParameters) {
            RELSW10aSecretKeyParameters that = (RELSW10aSecretKeyParameters) anOjbect;
            //Compare id
            if (!this.id.equals(that.getId())) {
                return false;
            }
            //Compare elementId
            if (!Utils.isEqualElement(this.elementId, that.getElementId())) {
                return false;
            }
            //Compare d0
            if (!Utils.isEqualElement(this.d0, that.getD0())) {
                return false;
            }
            //Compare d1
            if (!Utils.isEqualElement(this.d1, that.getD1())) {
                return false;
            }
            //Compare d2
            if (!Utils.isEqualElement(this.d2, that.getD2())) {
                return false;
            }
            return true;
        }
        return false;
    }
}
