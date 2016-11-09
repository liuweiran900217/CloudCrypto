package cn.edu.buaa.crypto.encryption.ibbe.del07.serialization;

import cn.edu.buaa.crypto.utils.SerializationUtils;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibbe.del07.IBBEDel07Engine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07CipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07SecretKeySerParameter;
import cn.edu.buaa.crypto.algebra.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2016/8/25.
 *
 * XML sserializer for Delerablée IBBE scheme.
 */
public class IBBEDel07XMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = IBBEDel07Engine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_W = "W";
    private static final String TAG_PK_V = "V";
    private static final String TAG_PK_HS = "Hs";
    private static final String TAG_PK_HI = "Hi";

    //Tags for master secret key
    private static final String TAG_MSK_G = "G";
    private static final String TAG_MSK_GAMMA = "Gamma";

    //Tags for secret key
    private static final String TAG_SK_ID = "Id";
    private static final String TAG_SK_SK = "sk";

    //Tags for ciphertexts
    private static final String TAG_CT_C1 = "C1";
    private static final String TAG_CT_C2 = "C2";

    private static final IBBEDel07XMLSerializer INSTANCE = new IBBEDel07XMLSerializer();

    private IBBEDel07XMLSerializer() { }

    public static IBBEDel07XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof IBBEDel07PublicKeySerParameter) {
            return getInstance().publicKeyParametersSerialization((IBBEDel07PublicKeySerParameter) cipherParameters);
        } else if (cipherParameters instanceof IBBEDel07MasterSecretKeySerParameter) {
            return getInstance().masterSecretKeyParametersSerialization((IBBEDel07MasterSecretKeySerParameter) cipherParameters);
        } else if (cipherParameters instanceof IBBEDel07SecretKeySerParameter) {
            return getInstance().secretKeyParametersSerialization((IBBEDel07SecretKeySerParameter) cipherParameters);
        } else if (cipherParameters instanceof IBBEDel07CipherSerParameter) {
            return getInstance().ciphertextParametersSerialization((IBBEDel07CipherSerParameter) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + TAG_SCHEME_NAME +
                    " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(IBBEDel07PublicKeySerParameter publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(IBBEDel07XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBBEDel07XMLSerializer.TYPE_PK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(publicKeyParameters.getMaxBroadcastReceiver()));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set w
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_W, publicKeyParameters.getW());
            //Set v
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_V, publicKeyParameters.getV());
            //Set hs
            SerializationUtils.SetElementArray(publicKeyParametersDocument, schemeElement, TAG_PK_HS, TAG_PK_HI, publicKeyParameters.getHs());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(IBBEDel07MasterSecretKeySerParameter masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(IBBEDel07XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBBEDel07XMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set g
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_G, masterSecretKeyParameters.getG());
            //Set gamma
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_GAMMA, masterSecretKeyParameters.getGamma());
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(IBBEDel07SecretKeySerParameter secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(IBBEDel07XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBBEDel07XMLSerializer.TYPE_SK);
            secretKeyDocument.appendChild(schemeElement);
            //Set Id
            SerializationUtils.SetString(secretKeyDocument, schemeElement, TAG_SK_ID, secretKeyParameters.getId());
            //Set sk
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_SK, secretKeyParameters.getSecretKey());
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(IBBEDel07CipherSerParameter ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(IBBEDel07XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, IBBEDel07XMLSerializer.TYPE_CT);
            ciphertextDocument.appendChild(schemeElement);
            //Set C1
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C1, ciphertextParameters.getC1());
            //Set C2
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C2, ciphertextParameters.getC2());
            return ciphertextDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        Element schemeElement = document.getDocumentElement();
        String cipherParameterType = schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_TYPE);
        if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_PK)){
            return getInstance().publicKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_MSK)){
            return getInstance().masterSecretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_SK)) {
            return getInstance().secretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_CT)) {
            return getInstance().ciphertextParametersDeserialization(pairingParameters, schemeElement);
        } else {
            throw new InvalidParameterException("Illegal " + TAG_SCHEME_NAME + " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element w = null;
        it.unisa.dia.gas.jpbc.Element v = null;
        it.unisa.dia.gas.jpbc.Element[] hs = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_W)) {
                //Set w
                w = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_V)) {
                //Set v
                v = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.GT);
            } else if (node.getNodeName().equals(TAG_PK_HS)) {
                //Set hs
                hs = SerializationUtils.GetElementArray(pairing, node, TAG_PK_HI, SerializationUtils.PairingGroupType.G2);
            }
        }
        return new IBBEDel07PublicKeySerParameter(pairingParameters, w, v, hs);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element gamma = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_MSK_G)) {
                //Set g
                g = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_MSK_GAMMA)) {
                //Set gamma
                gamma = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            }
        }
        return new IBBEDel07MasterSecretKeySerParameter(pairingParameters, g, gamma);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        String id = null;
        it.unisa.dia.gas.jpbc.Element sk = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_ID)) {
                //Set ID
                id = SerializationUtils.GetString(node);
            } else if (node.getNodeName().equals(TAG_SK_SK)) {
                //Set sk
                sk = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        it.unisa.dia.gas.jpbc.Element elementId = PairingUtils.MapToZr(pairing, id);
        return new IBBEDel07SecretKeySerParameter(pairingParameters, id, elementId, sk);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element C1 = null;
        it.unisa.dia.gas.jpbc.Element C2 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_C1)) {
                //Set C1
                C1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_C2)) {
                //Set C2
                C2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new IBBEDel07CipherSerParameter(pairingParameters, C1, C2);
    }
}
