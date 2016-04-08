package cn.edu.buaa.crypto.chameleonhash.schemes.czk04.serialization;

import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params.CHCZK04HashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params.CHCZK04PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params.CHCZK04SecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.w3c.dom.Document;

import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2016/4/8.
 */
public class CHCZK04XMLSerializer implements ChameleonHashXMLSerializer {
    private static final String TAG_SCHEME_NAME = CHCZK04Engine.SCHEME_NAME;
    //TAGs for Public Key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_Y = "Y";
    //TAGs for Secret Key
    private static final String TAG_SK_x = "X";

    private static final CHCZK04XMLSerializer INSTANCE = new CHCZK04XMLSerializer();

    private CHCZK04XMLSerializer() { }

    public static CHCZK04XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(Document document, ChameleonHashParameters chameleonHashParameters) {
//        if (chameleonHashParameters instanceof CHCZK04PublicKeyParameters) {
//            return getInstance().publicKeyParametersSerialization(document, (CHCZK04PublicKeyParameters) chameleonHashParameters);
//        } else if (chameleonHashParameters instanceof CHCZK04SecretKeyParameters) {
//            return getInstance().secretKeyParametersSerialization(document, (CHCZK04SecretKeyParameters) chameleonHashParameters);
//        } else if (chameleonHashParameters instanceof CHCZK04HashResultParameters) {
//            return getInstance().hashParametersSerialization(document, (CHCZK04HashResultParameters) chameleonHashParameters);
//        } else {
//            throw new InvalidParameterException("Invalid ChameleonHashParameters Instance of " + TAG_SCHEME_NAME
//                    + " Scheme, find" + chameleonHashParameters.getClass().getName());
//        }
        return null;
    }

    public Document documentSerialization(ChameleonHashParameters chameleonHashParameters) {
        return null;
    }

    public ChameleonHashParameters documentDeserialization(PairingParameters pairingParameters, org.w3c.dom.Document document) {
        return null;
    }
}
