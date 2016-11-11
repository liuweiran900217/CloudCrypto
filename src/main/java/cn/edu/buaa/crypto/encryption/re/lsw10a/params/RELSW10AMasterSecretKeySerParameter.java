package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/4/3.
 *
 * Lewko-Waters revocation encryption master secret key parameter.
 */
public class RELSW10AMasterSecretKeySerParameter extends PairingKeySerParameter {

    private final Element alpha;
    private final Element b;
    private final Element h;

    public RELSW10AMasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Element b, Element h) {
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
        if (anObject instanceof RELSW10AMasterSecretKeySerParameter) {
            RELSW10AMasterSecretKeySerParameter that = (RELSW10AMasterSecretKeySerParameter)anObject;
            if (!(PairingUtils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            if (!(PairingUtils.isEqualElement(this.b, that.getB()))) {
                return false;
            }
            if (!(PairingUtils.isEqualElement(this.h, that.getH()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
