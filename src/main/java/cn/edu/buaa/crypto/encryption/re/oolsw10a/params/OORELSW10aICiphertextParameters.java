package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/7.
 */
public class OORELSW10aICiphertextParameters extends PairingCiphertextParameters {
    private final int length;
    private final Element C0;
    private final Element[] C1s;
    private final Element[] C2s;
    private final Element Cv1;
    private final Element Cv2;
    private final Element[] Is;
    private final Element Iv;
    private final Element[] ss;
    private final Element sv;
    private final Element s;
    private final ChameleonHashSecretKeyParameters chameleonHashSecretKey;
    private final ChameleonHashResultParameters chameleonHashResult;

    public OORELSW10aICiphertextParameters(
            PairingParameters pairingParameters,
            int length, Element C0, Element[] C1s, Element[] C2s, Element Cv1, Element Cv2,
            Element[] Is, Element Iv, Element[] ss, Element sv, Element s,
            ChameleonHashSecretKeyParameters chameleonHashSecretKey, ChameleonHashResultParameters chameleonHashResult) {
        super(pairingParameters);
        this.length = length;
        this.C0 = C0.getImmutable();
        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.Cv1 = Cv1.getImmutable();
        this.Cv2 = Cv2.getImmutable();
        this.Is = ElementUtils.cloneImmutable(Is);
        this.Iv = Iv.getImmutable();
        this.ss = ElementUtils.cloneImmutable(ss);
        this.sv = sv.getImmutable();
        this.s = s.getImmutable();
        this.chameleonHashSecretKey = chameleonHashSecretKey;
        this.chameleonHashResult = chameleonHashResult;
    }

    public int getLength() { return this.length; }

    public Element getC0() { return this.C0.duplicate(); }

    public Element[] getC1s() { return Arrays.copyOf(this.C1s, this.C1s.length); }

    public Element getC1At(int index) { return this.C1s[index].duplicate(); }

    public Element[] getC2s() { return Arrays.copyOf(this.C2s, this.C2s.length); }

    public Element getC2At(int index) { return this.C2s[index].duplicate(); }

    public Element getCv1() { return this.Cv1.duplicate(); }

    public Element getCv2() { return this.Cv2.duplicate(); }

    public Element[] getIs() { return Arrays.copyOf(this.Is, this.Is.length); }

    public Element getIAt(int index) { return this.Is[index].duplicate(); }

    public Element getIv() { return this.Iv.duplicate(); }

    public Element[] getSs() { return Arrays.copyOf(this.ss, this.ss.length); }

    public Element getSAt(int index) { return this.ss[index].duplicate(); }

    public Element getSv() { return this.sv.duplicate(); }

    public Element getS() { return this.s.duplicate(); }

    public ChameleonHashSecretKeyParameters getChameleonHashSecretKey() {
        return this.chameleonHashSecretKey;
    }

    public ChameleonHashResultParameters getChameleonHashResut() {
        return this.chameleonHashResult;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof OORELSW10aICiphertextParameters) {
            OORELSW10aICiphertextParameters that = (OORELSW10aICiphertextParameters) anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            } else if (!Utils.isEqualElement(this.C0, that.getC0())) {
                return false;
            } else if (!Utils.isEqualElementArray(this.C1s, that.getC1s())) {
                return false;
            } else if (!Utils.isEqualElementArray(this.C2s, that.getC2s())) {
                return false;
            } else if (!Utils.isEqualElement(this.Cv1, that.getCv1())) {
                return false;
            } else if (!Utils.isEqualElement(this.Cv2, that.getCv2())) {
                return false;
            } else if (!Utils.isEqualElementArray(this.Is, that.getIs())) {
                return false;
            } else if (!Utils.isEqualElement(this.Iv, that.getIv())) {
                return false;
            } else if (!Utils.isEqualElementArray(this.ss, that.getSs())) {
                return false;
            } else if (!Utils.isEqualElement(this.sv, that.getSv())) {
                return false;
            } else if (!Utils.isEqualElement(this.s, that.getS())) {
                return false;
            } else if (!this.chameleonHashSecretKey.equals(that.getChameleonHashSecretKey())) {
                return false;
            } else if (!this.chameleonHashResult.equals(that.chameleonHashResult)) {
                return false;
            }
            return true;
        }
        return false;
    }
}
