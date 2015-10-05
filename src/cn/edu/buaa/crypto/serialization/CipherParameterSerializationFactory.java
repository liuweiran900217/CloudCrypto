package cn.edu.buaa.crypto.serialization;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.w3c.dom.*;


/**
 * Created by Weiran Liu on 15-10-2.
 */
public interface CipherParameterSerializationFactory {
    public static final String ATTRI_TYPE = "Type";
    public static final String ATTRI_INDEX = "Index";
    public static final String ATTRI_LENGTH = "Length";

    public static final String TYPE_PK = "PK";
    public static final String TYPE_MSK = "MSK";
    public static final String TYPE_SK = "SK";
    public static final String TYPE_CT = "CT";
    public static final String TYPE_ISK = "ISK";
    public static final String TYPE_ICT = "ICT";

    public Document documentSerialization(CipherParameters cipherParameters);
    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document);
}
