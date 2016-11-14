package cn.edu.buaa.crypto.encryption.re.lsw10a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption secret key parameter.
 */
public class RELSW10aSecretKeySerParameter extends PairingKeySerParameter {
    private final String id;
    private transient Element elementId;
    private final byte[] byteArrayElementId;

    private transient Element d0;
    private final byte[] byteArrayD0;

    private transient Element d1;
    private final byte[] byteArrayD1;

    private transient Element d2;
    private final byte[] byteArrayD2;

    public RELSW10aSecretKeySerParameter(PairingParameters pairingParameters,
                                         String id, Element elementId, Element d0, Element d1, Element d2) {
        super(true, pairingParameters);
        this.id = id;
        this.elementId = elementId.getImmutable();
        this.byteArrayElementId = this.elementId.toBytes();

        this.d0 = d0.getImmutable();
        this.byteArrayD0 = this.d0.toBytes();

        this.d1 = d1.getImmutable();
        this.byteArrayD1 = this.d1.toBytes();

        this.d2 = d2.getImmutable();
        this.byteArrayD2 = this.d2.toBytes();
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
        if (anOjbect instanceof RELSW10aSecretKeySerParameter) {
            RELSW10aSecretKeySerParameter that = (RELSW10aSecretKeySerParameter) anOjbect;
            //Compare id
            if (!this.id.equals(that.getId())) {
                return false;
            }
            //Compare elementId
            if (!PairingUtils.isEqualElement(this.elementId, that.getElementId())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayElementId, that.byteArrayElementId)) {
                return false;
            }
            //Compare d0
            if (!PairingUtils.isEqualElement(this.d0, that.getD0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD0, that.byteArrayD0)) {
                return false;
            }
            //Compare d1
            if (!PairingUtils.isEqualElement(this.d1, that.getD1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD1, that.byteArrayD1)) {
                return false;
            }
            //Compare d2
            if (!PairingUtils.isEqualElement(this.d2, that.getD2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD2, that.byteArrayD2)) {
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
        this.elementId = pairing.getZr().newElementFromBytes(this.byteArrayElementId);
        this.d0 = pairing.getG1().newElementFromBytes(this.byteArrayD0);
        this.d1 = pairing.getG1().newElementFromBytes(this.byteArrayD1);
        this.d2 = pairing.getG1().newElementFromBytes(this.byteArrayD2);
    }
}
