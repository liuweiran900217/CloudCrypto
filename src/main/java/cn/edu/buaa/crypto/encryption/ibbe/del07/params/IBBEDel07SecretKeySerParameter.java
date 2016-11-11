package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/8/23.
 *
 * Secret Key Parameters for Delerablée IBBE.
 */
public class IBBEDel07SecretKeySerParameter extends PairingKeySerParameter {
    private final String id;
    private final Element elementId;

    private final Element secretKey;

    public IBBEDel07SecretKeySerParameter(PairingParameters pairingParameters, String id, Element elementId, Element secretKey) {
        super(true, pairingParameters);
        this.secretKey = secretKey.getImmutable();
        this.id = id;
        this.elementId = elementId.getImmutable();
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
            //Compare secret key
            if (!PairingUtils.isEqualElement(this.secretKey, that.getSecretKey())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
