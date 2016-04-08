package cn.edu.buaa.crypto.chameleonhash.serialization;

import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashParameters;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.w3c.dom.*;

import javax.xml.bind.Element;

/**
 * Created by Weiran Liu on 2016/4/8.
 */
public interface ChameleonHashXMLSerializer {
    public static final String TYPE_PK = "PK";
    public static final String TYPE_SK = "SK";
    public static final String TYPE_HASH = "HASH";
    public static final String TYPE_RS = "RS";
    public static final String TYPE_RI = "RI";
    public static final String ATTRI_INDEX = "Index";
    public static final String ATTRI_LENGTH = "Length";

    public Document documentSerialization(ChameleonHashParameters chameleonHashParameters);

    public Document documentSerialization(Document document, ChameleonHashParameters chameleonHashParameters);

    public ChameleonHashParameters documentDeserialization(PairingParameters pairingParameters, Document document);
}
