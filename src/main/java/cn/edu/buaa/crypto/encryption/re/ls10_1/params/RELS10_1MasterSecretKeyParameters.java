package cn.edu.buaa.crypto.encryption.re.ls10_1.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/4/3.
 */
public class RELS10_1MasterSecretKeyParameters extends PairingKeyParameters {

    private final Element alpha;
    private final Element b;

    public RELS10_1MasterSecretKeyParameters(PairingParameters pairingParameters, Element alpha, Element b) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.b = b.getImmutable();
    }

    public Element get_alpha() { return this.alpha.duplicate(); };

    public Element get_b() { return this.b.duplicate(); };

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELS10_1MasterSecretKeyParameters) {
            RELS10_1MasterSecretKeyParameters that = (RELS10_1MasterSecretKeyParameters)anObject;
            if (!(Utils.isEqualElement(this.alpha, that.get_alpha()))) {
                return false;
            }
            if (!(Utils.isEqualElement(this.b, that.get_b()))) {
                return false;
            }
            return true;
        }
        return false;
    }
}
