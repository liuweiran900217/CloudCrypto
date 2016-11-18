package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE secret key parameter.
 */
public class KPABEGPSW06aSecretKeySerParameter extends PairingKeySerParameter {
    private final AccessControlParameter accessControlParameter;
    private final String[] rhos;

    private transient Element[] Ds;
    private final byte[][] byteArraysDs;

    public KPABEGPSW06aSecretKeySerParameter(PairingParameters pairingParameters,
                                             AccessControlParameter accessControlParameter, String[] rhos, Element[] Ds) {
        super(true, pairingParameters);

        this.accessControlParameter = accessControlParameter;
        this.rhos = rhos;

        this.Ds = ElementUtils.cloneImmutable(Ds);
        this.byteArraysDs = PairingUtils.GetElementArrayBytes(this.Ds);
    }

    public AccessControlParameter getAccessControlParameter() { return this.accessControlParameter; }

    public String[] getRhos() { return this.rhos; }

    public Element[] getDs() { return ElementUtils.cloneImmutable(Ds); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06aSecretKeySerParameter) {
            KPABEGPSW06aSecretKeySerParameter that = (KPABEGPSW06aSecretKeySerParameter)anObject;
            //Compare access policy
            if (!this.accessControlParameter.equals(that.accessControlParameter)) {
                return false;
            }
            if (!Arrays.equals(this.rhos, that.rhos)) {
                return false;
            }
            //Compare Ds
            if (!PairingUtils.isEqualElementArray(this.Ds, that.Ds)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysDs, that.byteArraysDs)) {
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
        this.Ds = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysDs, PairingUtils.PairingGroupType.G1);
    }
}