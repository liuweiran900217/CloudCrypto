package cn.edu.buaa.crypto.encryption.ibbe.del07.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/8/23.
 *
 * Secret Key Parameters for Delerablée IBBE.
 */
public class IBBEDel07SecretKeySerParameter extends PairingKeySerParameter {
    private final String id;
    private transient Element elementId;
    private final byte[] byteArrayElementId;

    private transient Element secretKey;
    private final byte[] byteArraySecretKey;

    public IBBEDel07SecretKeySerParameter(PairingParameters pairingParameters, String id, Element elementId, Element secretKey) {
        super(true, pairingParameters);

        this.secretKey = secretKey.getImmutable();
        this.byteArraySecretKey = this.secretKey.toBytes();

        this.id = id;
        this.elementId = elementId.getImmutable();
        this.byteArrayElementId = this.elementId.toBytes();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getSecretKey() { return this.secretKey.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBBEDel07SecretKeySerParameter) {
            IBBEDel07SecretKeySerParameter that = (IBBEDel07SecretKeySerParameter)anObject;
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
            //Compare secret key
            if (!PairingUtils.isEqualElement(this.secretKey, that.getSecretKey())) {
                return false;
            }
            if (!Arrays.equals(this.byteArraySecretKey, that.byteArraySecretKey)) {
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
        this.elementId = pairing.getZr().newElementFromBytes(this.byteArrayElementId).getImmutable();
        this.secretKey = pairing.getG1().newElementFromBytes(this.byteArraySecretKey).getImmutable();
    }
}
