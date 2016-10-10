package cn.edu.buaa.crypto.pairingkem.serialization;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.w3c.dom.*;


/**
 * Created by Weiran Liu on 15-10-2.
 */
public interface PairingParameterXMLSerializer {
    String ATTRI_TYPE = "Type";
    String ATTRI_INDEX = "Index";
    String ATTRI_LENGTH = "Length";
    String ATTRI_MAX_LENGTH = "MaxLength";
    String ATTRI_MAX_USER = "MaxUser";

    String TYPE_PK = "PK";
    String TYPE_MSK = "MSK";
    String TYPE_SK = "SK";
    String TYPE_CT = "CT";
    String TYPE_ISK = "ISK";
    String TYPE_ICT = "ICT";

    Document documentSerialization(CipherParameters cipherParameters);
    CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document);
}
