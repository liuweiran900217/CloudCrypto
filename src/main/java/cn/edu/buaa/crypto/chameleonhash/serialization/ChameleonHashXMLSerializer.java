package cn.edu.buaa.crypto.chameleonhash.serialization;

import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashParameters;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.w3c.dom.*;

/**
 * Created by Weiran Liu on 2016/4/8.
 *
 * Chameleon Hash Functions XML serializer.
 */
public interface ChameleonHashXMLSerializer {
    String ATTRI_TYPE = "Type";
    String TYPE_PK = "PK";
    String TYPE_SK = "SK";
    String TYPE_CH = "CH";
    String TAG_HASH_HASH = "HASH";
    String TAG_HASH_RESULT = "HASH_RESULT";
    String TAG_HASH_RS = "RS";
    String TAG_HASH_RI = "RI";
    String ATTRI_INDEX = "Index";

    public Document documentSerialization(ChameleonHashParameters chameleonHashParameters);

    public Document documentSerialization(Document document, Element rootElement, ChameleonHashParameters chameleonHashParameters);

    public ChameleonHashParameters documentDeserialization(PairingParameters pairingParameters, Document document);

    public ChameleonHashParameters documentDeserialization(PairingParameters pairingParameters, Document document, Element rootElement);
}
