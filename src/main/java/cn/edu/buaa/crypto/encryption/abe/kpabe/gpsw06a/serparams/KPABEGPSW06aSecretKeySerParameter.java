package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE secret key parameter.
 */
public class KPABEGPSW06aSecretKeySerParameter extends PairingKeySerParameter {
    private final AccessControlParameter accessControlParameter;

    private transient Map<String, Element> Ds;
    private final Map<String, byte[]> byteArraysDs;

    public KPABEGPSW06aSecretKeySerParameter(PairingParameters pairingParameters, AccessControlParameter accessControlParameter,
                                             Map<String, Element> Ds) {
        super(true, pairingParameters);

        this.accessControlParameter = accessControlParameter;

        this.Ds = new HashMap<String, Element>();
        this.byteArraysDs = new HashMap<String, byte[]>();
        for (String rho : Ds.keySet()) {
            Element elementRho = Ds.get(rho).duplicate().getImmutable();
            this.Ds.put(rho, elementRho);
            this.byteArraysDs.put(rho, elementRho.toBytes());
        }
    }

    public AccessControlParameter getAccessControlParameter() { return this.accessControlParameter; }

    public String[] getRhos() { return this.Ds.keySet().toArray(new String[1]); }

    public Element getDsAt(String rho) { return this.Ds.get(rho).duplicate(); }

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
            //Compare Ds
            if (!this.Ds.equals(that.Ds)) {
                return false;
            }
            //Compare byteArrayDs
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysDs, that.byteArraysDs)) {
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
        this.Ds = new HashMap<String, Element>();
        for (String rho : this.byteArraysDs.keySet()) {
            this.Ds.put(rho, pairing.getG1().newElementFromBytes(this.byteArraysDs.get(rho)));
        }
    }
}