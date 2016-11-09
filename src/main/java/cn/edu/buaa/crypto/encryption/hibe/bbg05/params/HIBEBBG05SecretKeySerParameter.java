package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05SecretKeySerParameter extends PairingKeySerParameter {

    private String[] ids;
    private Element[] elementIds;

    private Element a0;
    private Element a1;

    private Element[] bs;

    public HIBEBBG05SecretKeySerParameter(PairingParameters pairingParameters, String[] ids, Element[] elementIds,
                                          Element a0, Element a1, Element[] bs) {
        super(true, pairingParameters);

        this.a0 = a0.getImmutable();
        this.a1 = a1.getImmutable();
        this.bs = ElementUtils.cloneImmutable(bs);
        this.ids = new String[ids.length];

        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
        this.elementIds = ElementUtils.cloneImmutable(elementIds);
    }

    public int getLength() {
        return this.ids.length;
    }

    public String getIdAt(int index) { return this.ids[index]; }

    public String[] getIds() { return this.ids; }

    public Element getElementIdAt(int index) { return this.elementIds[index].duplicate(); }

    public Element[] getElementIds() { return this.elementIds; }

    public Element getA0() { return this.a0.duplicate(); }

    public Element getA1() { return this.a1.duplicate(); }

    public Element getBsAt(int index) { return this.bs[index].duplicate(); }

    public Element[] getBs() { return this.bs; }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof HIBEBBG05SecretKeySerParameter) {
            HIBEBBG05SecretKeySerParameter that = (HIBEBBG05SecretKeySerParameter)anOjbect;
            //Compare length
            if (this.getLength() != that.getLength()) {
                return false;
            }
            //Compare ids
            if (!Arrays.equals(this.ids, that.getIds())) {
                return false;
            }
            //Compare elementIds
            if (!PairingUtils.isEqualElementArray(this.elementIds, that.getElementIds())) {
                return false;
            }
            //Compare a0
            if (!PairingUtils.isEqualElement(this.a0, that.getA0())) {
                return false;
            }
            //Compare a1
            if (!PairingUtils.isEqualElement(this.a1, that.getA1())) {
                return false;
            }
            //Compare bs
            if (!PairingUtils.isEqualElementArray(this.bs, that.getBs())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
