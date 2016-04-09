package cn.edu.buaa.crypto.chameleonhash.schemes.kr00.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.CHKR00Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00HashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00PublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params.CHKR00SecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 16/4/9.
 */
public class CHKR00XMLSerializer implements ChameleonHashXMLSerializer {
    private static final String TAG_SCHEME_NAME = CHKR00Engine.SCHEME_NAME;
    //TAGs for Public Key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_Y = "Y";
    //TAGs for Secret Key
    private static final String TAG_SK_x = "X";
    private static final String TAG_SK_PK = "PK";

    private static final CHKR00XMLSerializer INSTANCE = new CHKR00XMLSerializer();

    private CHKR00XMLSerializer() { }

    public static CHKR00XMLSerializer getInstance(){
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
        if (chameleonHashParameters instanceof CHKR00PublicKeyParameters) {
            getInstance().publicKeyParametersSerialization(document, rootElement, (CHKR00PublicKeyParameters) chameleonHashParameters);
        } else if (chameleonHashParameters instanceof CHKR00SecretKeyParameters) {
            getInstance().secretKeyParametersSerialization(document, rootElement, (CHKR00SecretKeyParameters) chameleonHashParameters);
        } else if (chameleonHashParameters instanceof CHKR00HashResultParameters) {
            getInstance().hashResultParametersSerialization(document, rootElement, (CHKR00HashResultParameters) chameleonHashParameters);
        } else {
            throw new InvalidParameterException("Invalid ChameleonHashParameters Instance of " + TAG_SCHEME_NAME
                    + " Scheme, find" + chameleonHashParameters.getClass().getName());
        }
        return document;
    }

    private void publicKeyParametersSerialization(Document document, Element rootElement, CHKR00PublicKeyParameters publicKeyParameters) {
        rootElement.setAttribute(ChameleonHashXMLSerializer.ATTRI_TYPE, ChameleonHashXMLSerializer.TYPE_PK);
        //Set G
        SerializationUtils.SetElement(document, rootElement, this.TAG_PK_G, publicKeyParameters.getG());
        //Set Y
        SerializationUtils.SetElement(document, rootElement, this.TAG_PK_Y, publicKeyParameters.getY());
    }

    private void secretKeyParametersSerialization(Document document, Element rootElement, CHKR00SecretKeyParameters secretKeyParameters) {
        rootElement.setAttribute(ChameleonHashXMLSerializer.ATTRI_TYPE, ChameleonHashXMLSerializer.TYPE_SK);
        //Set x
        SerializationUtils.SetElement(document, rootElement, this.TAG_SK_x, secretKeyParameters.getX());
        //Set PublicKey
        Element publicKeyElement = document.createElement(this.TAG_SK_PK);
        rootElement.appendChild(publicKeyElement);
        CHKR00PublicKeyParameters publicKeyParameters = (CHKR00PublicKeyParameters)secretKeyParameters.getPublicKeyParameters();
        publicKeyParametersSerialization(document, publicKeyElement, publicKeyParameters);
    }

    private void hashResultParametersSerialization(Document document, Element rootElement, CHKR00HashResultParameters hashResultParameters) {
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
                String gString = node.getFirstChild().getNodeValue();
                g = pairing.getGT().newElementFromBytes(Hex.decode(gString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_Y)) {
                //Set y
                String yString = node.getFirstChild().getNodeValue();
                y = pairing.getGT().newElementFromBytes(Hex.decode(yString)).getImmutable();
            }
        }
        return new CHKR00PublicKeyParameters(pairingParameters, g, y);
    }

    private ChameleonHashSecretKeyParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element rootElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = rootElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element x = null;
        CHKR00PublicKeyParameters publicKeyParameters = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_x)) {
                //Set x
                String xString = node.getFirstChild().getNodeValue();
                x = pairing.getZr().newElementFromBytes(Hex.decode(xString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_PK)) {
                publicKeyParameters = (CHKR00PublicKeyParameters)publicKeyParametersDeserialization(pairingParameters, (Element) node);
            }
        }
        CHKR00SecretKeyParameters secretKeyParameters = new CHKR00SecretKeyParameters(pairingParameters, x);
        secretKeyParameters.setPublicKeyParameters(publicKeyParameters);
        return secretKeyParameters;
    }

    private ChameleonHashResultParameters hashResultParametersDeserialization(PairingParameters pairingParameters, Element rootElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int rLength = 1;
        NodeList nodeList = rootElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element hash = null;
        it.unisa.dia.gas.jpbc.Element hashResult = null;
        it.unisa.dia.gas.jpbc.Element[] Rs = new it.unisa.dia.gas.jpbc.Element[rLength];
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_HASH_HASH)) {
                //Set hash
                String hString = node.getFirstChild().getNodeValue();
                hash = pairing.getZr().newElementFromBytes(Hex.decode(hString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_HASH_RESULT)) {
                //Set hashResult
                String hashResultString = node.getFirstChild().getNodeValue();
                hashResult = pairing.getGT().newElementFromBytes(Hex.decode(hashResultString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_HASH_RS)) {
                //Set Rs
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_HASH_RI);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementRi = (Element) nodeHsList.item(j);
                    int index = Integer.valueOf(elementRi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String riString = elementRi.getFirstChild().getNodeValue();
                    Rs[index] = pairing.getZr().newElementFromBytes(Hex.decode(riString)).getImmutable();
                }
            }
        }
        return new CHKR00HashResultParameters(hash, hashResult, Rs);
    }
}
