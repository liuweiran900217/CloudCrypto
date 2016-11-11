package cn.edu.buaa.crypto.application.llw15.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Liu-Liu-Wu role-based access control patient access credential parameters
 */
public class RBACLLW15AccessCredentialPSerParameter extends PairingKeySerParameter {
    private final String id;
    private transient Element elementId;
    private final byte[] byteArrayElementId;

    private transient Element a0Prime;
    private final byte[] byteArrayA0Prime;

    private transient Element a1Prime;
    private final byte[] byteArrayA1Prime;

    private transient Element b0Prime;
    private final byte[] byteArrayB0Prime;

    private transient Element bvPrime;
    private final byte[] byteArrayBvPrime;

    private transient Element[] bsPrime;
    private final byte[][] byteArraysBsPrime;

    public RBACLLW15AccessCredentialPSerParameter(PairingParameters pairingParameters, String id, Element elementId,
                                                  Element a0Prime, Element a1Prime, Element b0Prime, Element bvPrime, Element[] bsPrime) {
        super(true, pairingParameters);

        this.a0Prime = a0Prime.getImmutable();
        this.byteArrayA0Prime = this.a0Prime.toBytes();

        this.a1Prime = a1Prime.getImmutable();
        this.byteArrayA1Prime = this.a1Prime.toBytes();

        this.b0Prime = b0Prime.getImmutable();
        this.byteArrayB0Prime = this.b0Prime.toBytes();

        this.bvPrime = bvPrime.getImmutable();
        this.byteArrayBvPrime = this.bvPrime.toBytes();

        this.bsPrime = ElementUtils.cloneImmutable(bsPrime);
        this.byteArraysBsPrime = PairingUtils.GetElementArrayBytes(this.bsPrime);

        this.id = id;
        this.elementId = elementId.getImmutable();
        this.byteArrayElementId = this.elementId.toBytes();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getA0Prime() { return this.a0Prime.duplicate(); }

    public Element getA1Prime() { return this.a1Prime.duplicate(); }

    public Element getB0Prime() { return this.b0Prime.duplicate(); }

    public Element getBvPrime() { return this.bvPrime.duplicate(); }

    public Element getBsPrimeAt(int index) { return this.bsPrime[index].duplicate(); }

    public Element[] getBsPrime() { return this.bsPrime; }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof RBACLLW15AccessCredentialPSerParameter) {
            RBACLLW15AccessCredentialPSerParameter that = (RBACLLW15AccessCredentialPSerParameter)anOjbect;
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
            //Compare a0Prime
            if (!PairingUtils.isEqualElement(this.a0Prime, that.getA0Prime())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayA0Prime, that.byteArrayA0Prime)) {
                return false;
            }
            //Compare a1Prime
            if (!PairingUtils.isEqualElement(this.a1Prime, that.getA1Prime())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayA1Prime, that.byteArrayA1Prime)) {
                return false;
            }
            //Compare b0Prime
            if (!PairingUtils.isEqualElement(this.b0Prime, that.getB0Prime())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayB0Prime, that.byteArrayB0Prime)) {
                return false;
            }
            //Compare bvPrime
            if (!PairingUtils.isEqualElement(this.bvPrime, that.getBvPrime())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayBvPrime, that.byteArrayBvPrime)) {
                return false;
            }
            //Compare bsPrime
            if (!PairingUtils.isEqualElementArray(this.bsPrime, that.getBsPrime())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysBsPrime, that.byteArraysBsPrime)) {
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
        this.a0Prime = pairing.getG1().newElementFromBytes(this.byteArrayA0Prime);
        this.a1Prime = pairing.getG1().newElementFromBytes(this.byteArrayA1Prime);
        this.b0Prime = pairing.getG1().newElementFromBytes(this.byteArrayB0Prime);
        this.bvPrime = pairing.getG1().newElementFromBytes(this.byteArrayBvPrime);
        this.bsPrime = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysBsPrime, PairingUtils.PairingGroupType.G1);
    }
}
