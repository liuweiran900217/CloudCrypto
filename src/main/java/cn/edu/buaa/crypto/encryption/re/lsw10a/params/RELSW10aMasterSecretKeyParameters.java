package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/4/3.
 */
public class RELSW10aMasterSecretKeyParameters extends PairingKeyParameters {

    private final Element alpha;
    private final Element b;
    private final Element h;

    public RELSW10aMasterSecretKeyParameters(PairingParameters pairingParameters, Element alpha, Element b, Element h) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.b = b.getImmutable();
        this.h = h.getImmutable();
    }

    public Element getAlpha() { return this.alpha.duplicate(); }

    public Element getB() { return this.b.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10aMasterSecretKeyParameters) {
            RELSW10aMasterSecretKeyParameters that = (RELSW10aMasterSecretKeyParameters)anObject;
            if (!(Utils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            if (!(Utils.isEqualElement(this.b, that.getB()))) {
                return false;
            }
            if (!(Utils.isEqualElement(this.h, that.getH()))) {
                return false;
            }
            return true;
        }
        return false;
    }
}
