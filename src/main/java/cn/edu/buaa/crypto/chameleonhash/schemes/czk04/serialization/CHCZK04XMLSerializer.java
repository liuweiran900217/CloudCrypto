package cn.edu.buaa.crypto.chameleonhash.schemes.czk04.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params.CHCZK04HashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params.CHCZK04PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params.CHCZK04SecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serialization.RELSW10aXMLSerializer;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
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
    private static final String TAG_SK_PK = "PK";

    private static final CHCZK04XMLSerializer INSTANCE = new CHCZK04XMLSerializer();

    private CHCZK04XMLSerializer() { }

    public static CHCZK04XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(ChameleonHashParameters chameleonHashParameters) {
        try {
            Document chameleonHashDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = chameleonHashDocument.createElement(this.TAG_SCHEME_NAME);
            chameleonHashDocument.appendChild(schemeElement);
            return this.documentSerialization(chameleonHashDocument, schemeElement, chameleonHashParameters);
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    public Document documentSerialization(Document document, Element rootElement, ChameleonHashParameters chameleonHashParameters) {
        if (chameleonHashParameters instanceof CHCZK04PublicKeyParameters) {
            getInstance().publicKeyParametersSerialization(document, rootElement, (CHCZK04PublicKeyParameters) chameleonHashParameters);
        } else if (chameleonHashParameters instanceof CHCZK04SecretKeyParameters) {
            getInstance().secretKeyParametersSerialization(document, rootElement, (CHCZK04SecretKeyParameters) chameleonHashParameters);
        } else if (chameleonHashParameters instanceof CHCZK04HashResultParameters) {
            getInstance().hashResultParametersSerialization(document, rootElement, (CHCZK04HashResultParameters) chameleonHashParameters);
        } else {
            throw new InvalidParameterException("Invalid ChameleonHashParameters Instance of " + TAG_SCHEME_NAME
                    + " Scheme, find" + chameleonHashParameters.getClass().getName());
        }
        return document;
    }

    private void publicKeyParametersSerialization(Document document, Element rootElement, CHCZK04PublicKeyParameters publicKeyParameters) {
        rootElement.setAttribute(ChameleonHashXMLSerializer.ATTRI_TYPE, ChameleonHashXMLSerializer.TYPE_PK);
        //Set G
        SerializationUtils.SetElement(document, rootElement, this.TAG_PK_G, publicKeyParameters.getG());
        //Set Y
        SerializationUtils.SetElement(document, rootElement, this.TAG_PK_Y, publicKeyParameters.getY());
    }

    private void secretKeyParametersSerialization(Document document, Element rootElement, CHCZK04SecretKeyParameters secretKeyParameters) {
        rootElement.setAttribute(ChameleonHashXMLSerializer.ATTRI_TYPE, ChameleonHashXMLSerializer.TYPE_SK);
        //Set x
        SerializationUtils.SetElement(document, rootElement, this.TAG_SK_x, secretKeyParameters.getX());
        //Set PublicKey
        Element publicKeyElement = document.createElement(this.TAG_SK_PK);
        rootElement.appendChild(publicKeyElement);
        CHCZK04PublicKeyParameters publicKeyParameters = (CHCZK04PublicKeyParameters)secretKeyParameters.getPublicKeyParameters();
        publicKeyParametersSerialization(document, publicKeyElement, publicKeyParameters);
    }

    private void hashResultParametersSerialization(Document document, Element rootElement, CHCZK04HashResultParameters hashResultParameters) {
        rootElement.setAttribute(ChameleonHashXMLSerializer.ATTRI_TYPE, ChameleonHashXMLSerializer.TYPE_CH);
        //Set hash
        SerializationUtils.SetElement(document, rootElement, ChameleonHashXMLSerializer.TAG_HASH_HASH, hashResultParameters.getHashMessage());
        //Set hashResult
        SerializationUtils.SetElement(document, rootElement, ChameleonHashXMLSerializer.TAG_HASH_RESULT, hashResultParameters.getHashResult());
        //Set rArray
        SerializationUtils.SetElementArray(document, rootElement,
                ChameleonHashXMLSerializer.TAG_HASH_RS, ChameleonHashXMLSerializer.TAG_HASH_RI, hashResultParameters.getRs());
    }

    public ChameleonHashParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        Element schemeElement = document.getDocumentElement();
        return documentDeserialization(pairingParameters, document, schemeElement);
    }


    public ChameleonHashParameters documentDeserialization(PairingParameters pairingParameters, Document document, Element rootElement) {
        String chameleonHashParametersType = rootElement.getAttribute(ChameleonHashXMLSerializer.ATTRI_TYPE);
        if (chameleonHashParametersType.equals(ChameleonHashXMLSerializer.TYPE_PK)){
            return getInstance().publicKeyParametersDeserialization(pairingParameters, rootElement);
        } else if (chameleonHashParametersType.equals(ChameleonHashXMLSerializer.TYPE_SK)) {
            return getInstance().secretKeyParametersDeserialization(pairingParameters, rootElement);
        } else if (chameleonHashParametersType.equals(ChameleonHashXMLSerializer.TYPE_CH)) {
            return getInstance().hashResultParametersDeserialization(pairingParameters, rootElement);
        } else {
            throw new InvalidParameterException("Illegal " + TAG_SCHEME_NAME +
                    " Document Type, find " + chameleonHashParametersType);
        }
    }

    private ChameleonHashPublicKeyParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element rootElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = rootElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element y = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                g = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.GT);
            } else if (node.getNodeName().equals(TAG_PK_Y)) {
                //Set y
                y = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.GT);
            }
        }
        return new CHCZK04PublicKeyParameters(pairingParameters, g, y);
    }

    private ChameleonHashSecretKeyParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element rootElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = rootElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element x = null;
        CHCZK04PublicKeyParameters publicKeyParameters = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_x)) {
                //Set x
                x = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_SK_PK)) {
                publicKeyParameters = (CHCZK04PublicKeyParameters)publicKeyParametersDeserialization(pairingParameters, (Element) node);
            }
        }
        CHCZK04SecretKeyParameters secretKeyParameters = new CHCZK04SecretKeyParameters(pairingParameters, x);
        secretKeyParameters.setPublicKeyParameters(publicKeyParameters);
        return secretKeyParameters;
    }

    private ChameleonHashResultParameters hashResultParametersDeserialization(PairingParameters pairingParameters, Element rootElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int rLength = 3;
        NodeList nodeList = rootElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element hash = null;
        it.unisa.dia.gas.jpbc.Element hashResult = null;
        it.unisa.dia.gas.jpbc.Element[] Rs = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_HASH_HASH)) {
                //Set hash
                hash = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_HASH_RESULT)) {
                //Set hashResult
                hashResult = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.GT);
            } else if (node.getNodeName().equals(TAG_HASH_RS)) {
                //Set Rs
                Rs = SerializationUtils.GetElementArray(pairing, node, TAG_HASH_RI, SerializationUtils.PairingGroupType.GT);
            }
        }
        return new CHCZK04HashResultParameters(hash, hashResult, Rs);
    }
}
