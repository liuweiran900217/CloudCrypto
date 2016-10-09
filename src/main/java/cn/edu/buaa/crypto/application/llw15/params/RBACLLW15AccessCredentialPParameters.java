package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Liu-Liu-Wu role-based access control patient access credential parameters
 */
public class RBACLLW15AccessCredentialPParameters extends PairingKeyParameters {
    private final String id;
    private final Element elementId;

    private final Element a0Prime;
    private final Element a1Prime;
    private final Element b0Prime;
    private final Element bvPrime;
    private final Element[] bsPrime;


    public RBACLLW15AccessCredentialPParameters(PairingParameters pairingParameters, String id, Element elementId,
                                         Element a0Prime, Element a1Prime, Element b0Prime, Element bvPrime, Element[] bsPrime) {
        super(true, pairingParameters);

        this.a0Prime = a0Prime.getImmutable();
        this.a1Prime = a1Prime.getImmutable();
        this.b0Prime = b0Prime.getImmutable();
        this.bvPrime = bvPrime.getImmutable();
        this.bsPrime = ElementUtils.cloneImmutable(bsPrime);
        this.id = new String(id);
        this.elementId = elementId.getImmutable();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getA0Prime() { return this.a0Prime.duplicate(); }

    public Element getA1Prime() { return this.a1Prime.duplicate(); }

    public Element getB0Prime() { return this.b0Prime.duplicate(); }

    public Element getBvPrime() { return this.bvPrime.duplicate(); }

    public Element getBsPrimeAt(int index) { return this.bsPrime[index].duplicate(); }

    public Element[] getBsPrime() { return Arrays.copyOf(bsPrime, bsPrime.length); }

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
            if (!PairingUtils.isEqualElement(this.elementId, that.getElementId())) {
                return false;
            }
            //Compare a0Prime
            if (!PairingUtils.isEqualElement(this.a0Prime, that.getA0Prime())) {
                return false;
            }
            //Compare a1Prime
            if (!PairingUtils.isEqualElement(this.a1Prime, that.getA1Prime())) {
                return false;
            }
            //Compare b0Prime
            if (!PairingUtils.isEqualElement(this.b0Prime, that.getB0Prime())) {
                return false;
            }
            //Compare bvPrime
            if (!PairingUtils.isEqualElement(this.bvPrime, that.getBvPrime())) {
                return false;
            }
            //Compare bsPrime
            if (!PairingUtils.isEqualElementArray(this.bsPrime, that.getBsPrime())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
