package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/4/7.
 */
public class OORELSW10aCiphertextParameters extends PairingCiphertextParameters {
    private final int length;
    private final Element C0;
    private final Element[] C1s, C2s, Imalls;
    private final Element Cv1;
    private final Element Cv2;
    private final ChameleonHashPublicKeyParameters chameleonHashPublicKeyParameters;
    private final ChameleonHashResultParameters chameleonHashResultParameters;

    public OORELSW10aCiphertextParameters(PairingParameters parameters, int length,
                                          Element C0, Element[] C1s, Element[] C2s, Element[] Imalls, Element Cv1, Element Cv2,
                                          ChameleonHashPublicKeyParameters chameleonHashPublicKeyParameters,
                                          ChameleonHashResultParameters chameleonHashResultParameters) {
        super(parameters);
        this.length = length;
        this.C0 = C0.getImmutable();
        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.Imalls = ElementUtils.cloneImmutable(Imalls);
        this.Cv1 = Cv1.getImmutable();
        this.Cv2 = Cv2.getImmutable();
        this.chameleonHashPublicKeyParameters = chameleonHashPublicKeyParameters;
        this.chameleonHashResultParameters = chameleonHashResultParameters;
    }

    public OORELSW10aCiphertextParameters(PairingParameters parameters, int length,
                                          Element C0, Element[] C1s, Element[] C2s, Element Cv1, Element Cv2,
                                          ChameleonHashPublicKeyParameters chameleonHashPublicKeyParameters,
                                          ChameleonHashResultParameters chameleonHashResultParameters) {
        super(parameters);
        this.length = length;
        this.C0 = C0.getImmutable();
        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.Imalls = new Element[this.length];
        Pairing pairing = PairingFactory.getPairing(parameters);
        for (int i=0; i<this.Imalls.length; i++) {
            this.Imalls[i] = pairing.getZr().newZeroElement().getImmutable();
        }
        this.Cv1 = Cv1.getImmutable();
        this.Cv2 = Cv2.getImmutable();
        this.chameleonHashPublicKeyParameters = chameleonHashPublicKeyParameters;
        this.chameleonHashResultParameters = chameleonHashResultParameters;
    }

    public int getLength() {
        return this.length;
    }

    public Element getC0() {
        return this.C0.duplicate();
    }

    public Element[] getC1s() {
        return ElementUtils.cloneImmutable(this.C1s);
    }

    public Element getC1At(int index) {
        return this.C1s[index].duplicate();
    }

    public Element[] getC2s() {
        return ElementUtils.cloneImmutable(this.C2s);
    }

    public Element getC2At(int index) {
        return this.C2s[index].duplicate();
    }

    public Element[] getImalls() {
        return ElementUtils.cloneImmutable(this.Imalls);
    }

    public Element getImallAt(int index) {
        return this.Imalls[index].duplicate();
    }

    public Element getCv1() {
        return this.Cv1.duplicate();
    }

    public Element getCv2() {
        return this.Cv2.duplicate();
    }

    public ChameleonHashPublicKeyParameters getChameleonHashPublicKeyParameters() {
        return this.chameleonHashPublicKeyParameters;
    }

    public ChameleonHashResultParameters getChameleonHashResultParameters() {
        return this.chameleonHashResultParameters;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof OORELSW10aCiphertextParameters) {
            OORELSW10aCiphertextParameters that = (OORELSW10aCiphertextParameters) anObject;
            //Compare length
            if (this.length != that.getLength()) { return false; }
            else if (!Utils.isEqualElement(this.C0, that.getC0())) { return false; }
            else if (!Utils.isEqualElementArray(this.C1s, that.getC1s())) { return false; }
            else if (!Utils.isEqualElementArray(this.C2s, that.getC2s())) { return false; }
            else if (!Utils.isEqualElementArray(this.Imalls, that.getImalls())) { return false; }
            else if (!Utils.isEqualElement(this.Cv1, that.getCv1())) { return false; }
            else if (!Utils.isEqualElement(this.Cv2, that.getCv2())) { return false; }
            else if (!this.chameleonHashPublicKeyParameters.equals(that.getChameleonHashPublicKeyParameters())) { return false; }
            else if (!this.chameleonHashResultParameters.equals(that.getChameleonHashResultParameters())) { return false; }
            return true;
        }
        return false;
    }
}
