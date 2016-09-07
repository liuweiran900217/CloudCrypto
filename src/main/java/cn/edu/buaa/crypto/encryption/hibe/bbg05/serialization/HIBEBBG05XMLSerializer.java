package cn.edu.buaa.crypto.encryption.hibe.bbg05.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05SecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 15/11/14.
 */
public class HIBEBBG05XMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = HIBEBBG05Engine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_G1 = "G1";
    private static final String TAG_PK_G2 = "G2";
    private static final String TAG_PK_G3 = "G3";
    private static final String TAG_PK_HS = "Hs";
    private static final String TAG_PK_HI = "Hi";

    //Tags for master secret key
    private static final String TAG_MSK_G2ALPHA = "G2Alpha";

    //Tags for secret key
    private static final String TAG_SK_A0 = "a0";
    private static final String TAG_SK_A1 = "a1";
    private static final String TAG_SK_BS = "bs";
    private static final String TAG_SK_BI = "bi";
    private static final String TAG_SK_IDS = "Ids";
    private static final String TAG_SK_IDI = "Idi";

    //Tags for ciphertexts
    private static final String TAG_CT_B = "B";
    private static final String TAG_CT_C = "C";

    private static final HIBEBBG05XMLSerializer INSTANCE = new HIBEBBG05XMLSerializer();

    private HIBEBBG05XMLSerializer() { }

    public static HIBEBBG05XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof HIBEBBG05PublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((HIBEBBG05PublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBBG05MasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((HIBEBBG05MasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBBG05SecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((HIBEBBG05SecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBBG05CiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((HIBEBBG05CiphertextParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + HIBEBBG05Engine.SCHEME_NAME
                    + " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(HIBEBBG05PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(HIBEBBG05XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_PK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(publicKeyParameters.getMaxLength()));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G, publicKeyParameters.getG());
            //Set g1
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G1, publicKeyParameters.getG1());
            //Set g2
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G2, publicKeyParameters.getG2());
            //Set g3
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G3, publicKeyParameters.getG3());
            //Set h
            SerializationUtils.SetElementArray(publicKeyParametersDocument, schemeElement, TAG_PK_HS, TAG_PK_HI, publicKeyParameters.getHs());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(HIBEBBG05MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(HIBEBBG05XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set g2Alpha
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_G2ALPHA, masterSecretKeyParameters.getG2Alpha());
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(HIBEBBG05SecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(HIBEBBG05XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_SK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(secretKeyParameters.getLength()));
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(secretKeyParameters.getBs().length));
            secretKeyDocument.appendChild(schemeElement);
            //Set Ids
            SerializationUtils.SetStringArray(secretKeyDocument, schemeElement, TAG_SK_IDS, TAG_SK_IDI, secretKeyParameters.getIds());
            //Set a0
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_A0, secretKeyParameters.getA0());
            //Set a1
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_A1, secretKeyParameters.getA1());
            //Set bs
            SerializationUtils.SetElementArray(secretKeyDocument, schemeElement, TAG_SK_BS, TAG_SK_BI, secretKeyParameters.getBs());
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(HIBEBBG05CiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(HIBEBBG05XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_CT);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(ciphertextParameters.getLength()));
            ciphertextDocument.appendChild(schemeElement);
            //Set B
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_B, ciphertextParameters.getB());
            //Set C
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C, ciphertextParameters.getC());
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
            throw new InvalidParameterException("Illegal " + HIBEBBG05Engine.SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxLength = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element g1 = null;
        it.unisa.dia.gas.jpbc.Element g2 = null;
        it.unisa.dia.gas.jpbc.Element g3 = null;
        it.unisa.dia.gas.jpbc.Element[] hs = new it.unisa.dia.gas.jpbc.Element[maxLength];
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                String gString = node.getFirstChild().getNodeValue();
                g = pairing.getG1().newElementFromBytes(Hex.decode(gString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_G1)) {
                //Set g1
                String g1String = node.getFirstChild().getNodeValue();
                g1 = pairing.getG1().newElementFromBytes(Hex.decode(g1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_G2)) {
                //Set g2
                String g2String = node.getFirstChild().getNodeValue();
                g2 = pairing.getG1().newElementFromBytes(Hex.decode(g2String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_G3)) {
                //Set g3
                String g3String = node.getFirstChild().getNodeValue();
                g3 = pairing.getG1().newElementFromBytes(Hex.decode(g3String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_PK_HS)) {
                //Set hs
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_PK_HI);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementHi = (Element)nodeHsList.item(j);
                    int index = Integer.valueOf(elementHi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String hiString = elementHi.getFirstChild().getNodeValue();
                    hs[index] = pairing.getG1().newElementFromBytes(Hex.decode(hiString)).getImmutable();
                }
            }
        }
        return new HIBEBBG05PublicKeyParameters(pairingParameters, g, g1, g2, g3, hs);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g2Alpha = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            //Set gaAlpha
            if (node.getNodeName().equals(TAG_MSK_G2ALPHA)) {
                String g2AlphaString = node.getFirstChild().getNodeValue();
                g2Alpha = pairing.getG1().newElementFromBytes(Hex.decode(g2AlphaString)).getImmutable();
            }
        }
        return new HIBEBBG05MasterSecretKeyParameters(pairingParameters, g2Alpha);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        int maxLength = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_MAX_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        String[] ids = new String[length];
        it.unisa.dia.gas.jpbc.Element[] elementIds;
        it.unisa.dia.gas.jpbc.Element a0 = null;
        it.unisa.dia.gas.jpbc.Element a1 = null;
        it.unisa.dia.gas.jpbc.Element[] bs = new it.unisa.dia.gas.jpbc.Element[maxLength];
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_A0)) {
                //Set a0
                String a0String = node.getFirstChild().getNodeValue();
                a0 = pairing.getG1().newElementFromBytes(Hex.decode(a0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_A1)) {
                //Set a1
                String a1String = node.getFirstChild().getNodeValue();
                a1 = pairing.getG1().newElementFromBytes(Hex.decode(a1String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_BS)) {
                //Set bs
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_SK_BI);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementBi = (Element) nodeHsList.item(j);
                    int index = Integer.valueOf(elementBi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String biString = elementBi.getFirstChild().getNodeValue();
                    bs[index] = pairing.getG1().newElementFromBytes(Hex.decode(biString)).getImmutable();
                }
            } else if (node.getNodeName().equals(TAG_SK_IDS)) {
                //Set Ids
                ids = SerializationUtils.GetStringArray(node, TAG_SK_IDI);
            }
        }
        elementIds = PairingUtils.MapToZr(pairing, ids);
        return new HIBEBBG05SecretKeyParameters(pairingParameters, ids, elementIds, a0, a1, bs);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element B = null;
        it.unisa.dia.gas.jpbc.Element C = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_B)) {
                //Set B
                String bString = node.getFirstChild().getNodeValue();
                B = pairing.getG1().newElementFromBytes(Hex.decode(bString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_CT_C)) {
                //Set C
                String cString = node.getFirstChild().getNodeValue();
                C = pairing.getG1().newElementFromBytes(Hex.decode(cString)).getImmutable();
            }
        }
        return new HIBEBBG05CiphertextParameters(pairingParameters, length, B, C);
    }
}
