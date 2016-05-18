package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 */
public class RBACLLW15AccessCredentialPParameters extends PairingKeyParameters {
    private final String id;
    private final Element elementId;

    private final Element a0;
    private final Element a1;
    private final Element b0;
    private final Element bv;
    private final Element[] bs;


    public RBACLLW15AccessCredentialPParameters(PairingParameters pairingParameters, String id, Element elementId,
                                         Element a0, Element a1, Element b0, Element bv, Element[] bs) {
        super(true, pairingParameters);

        this.a0 = a0.getImmutable();
        this.a1 = a1.getImmutable();
        this.b0 = b0.getImmutable();
        this.bv = bv.getImmutable();
        this.bs = ElementUtils.cloneImmutable(bs);
        this.id = new String(id);
        this.elementId = elementId.getImmutable();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getA0() { return this.a0.duplicate(); }

    public Element getA1() { return this.a1.duplicate(); }

    public Element getB0() { return this.b0.duplicate(); }

    public Element getBv() { return this.bv.duplicate(); }

    public Element getBsAt(int index) { return this.bs[index].duplicate(); }

    public Element[] getBs() { return Arrays.copyOf(bs, bs.length); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof RBACLLW15AccessCredentialPParameters) {
            RBACLLW15AccessCredentialPParameters that = (RBACLLW15AccessCredentialPParameters)anOjbect;
            //Compare id
            if (!this.id.equals(that.getId())) {
                return false;
            }
            //Compare elementId
            if (!Utils.isEqualElement(this.elementId, that.getElementId())) {
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
            //Compare b0
            if (!Utils.isEqualElement(this.b0, that.getB0())) {
                return false;
            }
            //Compare bv
            if (!Utils.isEqualElement(this.bv, that.getBv())) {
                return false;
            }
            //Compare bs
            if (!Utils.isEqualElementArray(this.bs, that.getBs())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
