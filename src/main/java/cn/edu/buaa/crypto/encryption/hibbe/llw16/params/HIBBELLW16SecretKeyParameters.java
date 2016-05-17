package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16SecretKeyParameters extends PairingKeyParameters {
    private final String[] ids;
    private final Element[] elementIds;

    private final Element a0;
    private final Element a1;
    private final Element[] bs;


    public HIBBELLW16SecretKeyParameters(PairingParameters pairingParameters, String[] ids, Element[] elementIds,
                                         Element a0, Element a1, Element[] bs) {
        super(true, pairingParameters);

        this.a0 = a0.getImmutable();
        this.a1 = a1.getImmutable();
        this.bs = ElementUtils.cloneImmutable(bs);
        this.ids = new String[ids.length];

        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
        this.elementIds = ElementUtils.cloneImmutable(elementIds);
    }

    public String getIdAt(int index) { return this.ids[index]; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public Element getElementIdAt(int index) { return this.elementIds[index].duplicate(); }

    public Element[] getElementIds() { return Arrays.copyOf(elementIds, elementIds.length); }

    public Element getA0() { return this.a0.duplicate(); }

    public Element getA1() { return this.a1.duplicate(); }

    public Element getBsAt(int index) { return this.bs[index].duplicate(); }

    public Element[] getBs() { return Arrays.copyOf(bs, bs.length); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof HIBBELLW16SecretKeyParameters) {
            HIBBELLW16SecretKeyParameters that = (HIBBELLW16SecretKeyParameters)anOjbect;
            //Compare ids
            if (!Arrays.equals(this.ids, that.getIds())) {
                return false;
            }
            //Compare elementIds
            if (!Utils.isEqualElementArray(this.elementIds, that.getElementIds())) {
                return false;
            }
            //Compare a0
            if (!Utils.isEqualElement(this.a0, that.getA0())) {
                return false;
            }
            //Compare a1
            if (!Utils.isEqualElement(this.a1, that.getA1())) {
                return false;
            }
            //Compare bs
            if (!Utils.isEqualElementArray(this.bs, that.getBs())) {
                return false;
            }
            return true;
        }
        return false;
    }
}

