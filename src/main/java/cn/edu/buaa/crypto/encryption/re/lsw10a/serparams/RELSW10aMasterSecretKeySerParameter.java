package cn.edu.buaa.crypto.encryption.re.lsw10a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/4/3.
 *
 * Lewko-Waters revocation encryption master secret key parameter.
 */
public class RELSW10aMasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element alpha;
    private final byte[] byteArrayAlpha;

    private transient Element b;
    private final byte[] byteArrayB;

    private transient Element h;
    private final byte[] byteArrayH;

    public RELSW10aMasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Element b, Element h) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.byteArrayAlpha = this.alpha.toBytes();

        this.b = b.getImmutable();
        this.byteArrayB = this.b.toBytes();

        this.h = h.getImmutable();
        this.byteArrayH = this.h.toBytes();
    }

    public Element getAlpha() { return this.alpha.duplicate(); }

    public Element getB() { return this.b.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10aMasterSecretKeySerParameter) {
            RELSW10aMasterSecretKeySerParameter that = (RELSW10aMasterSecretKeySerParameter)anObject;
            if (!(PairingUtils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayAlpha, that.byteArrayAlpha)) {
                return false;
            }
            if (!(PairingUtils.isEqualElement(this.b, that.getB()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayB, that.byteArrayB)) {
                return false;
            }
            if (!(PairingUtils.isEqualElement(this.h, that.getH()))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.alpha = pairing.getZr().newElementFromBytes(this.byteArrayAlpha).getImmutable();
        this.b = pairing.getZr().newElementFromBytes(this.byteArrayB).getImmutable();
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
    }
}
