package cn.edu.buaa.crypto.encryption.hibe.bbg05.serialization;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.hibe.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05SecretKeyParameters;
import cn.edu.buaa.crypto.serialization.CipherParameterXMLSerializer;
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
 * Created by liuweiran on 15/11/14.
 */
public class HIBEBBG05XMLSerializer implements CipherParameterXMLSerializer {
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
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, CipherParameterXMLSerializer.TYPE_PK);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(publicKeyParameters.getMaxLength()));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            Element gElement = publicKeyParametersDocument.createElement(TAG_PK_G);
            String gString = new String(Hex.encode(publicKeyParameters.getG().toBytes()));
            Text gText = publicKeyParametersDocument.createTextNode(gString);
            schemeElement.appendChild(gElement);
            gElement.appendChild(gText);
            //Set g1
            Element g1Element = publicKeyParametersDocument.createElement(TAG_PK_G1);
            String g1String = new String(Hex.encode(publicKeyParameters.getG1().toBytes()));
            Text g1Text = publicKeyParametersDocument.createTextNode(g1String);
            schemeElement.appendChild(g1Element);
            g1Element.appendChild(g1Text);
            //Set g2
            Element g2Element = publicKeyParametersDocument.createElement(TAG_PK_G2);
            String g2String = new String(Hex.encode(publicKeyParameters.getG2().toBytes()));
            Text g2Text = publicKeyParametersDocument.createTextNode(g2String);
            schemeElement.appendChild(g2Element);
            g2Element.appendChild(g2Text);
            //Set g3
            Element g3Element = publicKeyParametersDocument.createElement(TAG_PK_G3);
            String g3String = new String(Hex.encode(publicKeyParameters.getG3().toBytes()));
            Text g3Text = publicKeyParametersDocument.createTextNode(g3String);
            schemeElement.appendChild(g3Element);
            g3Element.appendChild(g3Text);
            //Set h
            Element hsElement = publicKeyParametersDocument.createElement(TAG_PK_HS);
            schemeElement.appendChild(hsElement);
            for (int i=0; i<publicKeyParameters.getMaxLength(); i++){
                Element hiElement = publicKeyParametersDocument.createElement(TAG_PK_HI);
                hiElement.setAttribute(CipherParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
                String hiString = new String(Hex.encode(publicKeyParameters.getHsAt(i).toBytes()));
                Text hiText = publicKeyParametersDocument.createTextNode(hiString);
                hsElement.appendChild(hiElement);
                hiElement.appendChild(hiText);
            }
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
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, CipherParameterXMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set g2Alpha
            Element g2AlphaElement = masterSecretKeyDocument.createElement(TAG_MSK_G2ALPHA);
            String g2AlphaString = new String(Hex.encode(masterSecretKeyParameters.getG2Alpha().toBytes()));
            Text g2AlphaText = masterSecretKeyDocument.createTextNode(g2AlphaString);
            schemeElement.appendChild(g2AlphaElement);
            g2AlphaElement.appendChild(g2AlphaText);

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
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, CipherParameterXMLSerializer.TYPE_SK);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(secretKeyParameters.getLength()));
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_MAX_LENGTH, Integer.toString(secretKeyParameters.getBs().length));
            secretKeyDocument.appendChild(schemeElement);
            //Set Ids
            Element idsElement = secretKeyDocument.createElement(TAG_SK_IDS);
            schemeElement.appendChild(idsElement);
            for (int i=0; i<secretKeyParameters.getLength(); i++) {
                Element idiElement = secretKeyDocument.createElement(TAG_SK_IDI);
                idiElement.setAttribute(CipherParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
                Text idiText = secretKeyDocument.createTextNode(secretKeyParameters.getIdAt(i));
                idsElement.appendChild(idiElement);
                idiElement.appendChild(idiText);
            }
            //Set a0
            Element a0Element = secretKeyDocument.createElement(HIBEBBG05XMLSerializer.TAG_SK_A0);
            String a0String = new String(Hex.encode(secretKeyParameters.getA0().toBytes()));
            Text a0Text = secretKeyDocument.createTextNode(a0String);
            schemeElement.appendChild(a0Element);
            a0Element.appendChild(a0Text);
            //Set a1
            Element a1Element = secretKeyDocument.createElement(HIBEBBG05XMLSerializer.TAG_SK_A1);
            String a1String = new String(Hex.encode(secretKeyParameters.getA1().toBytes()));
            Text a1Text = secretKeyDocument.createTextNode(a1String);
            schemeElement.appendChild(a1Element);
            a1Element.appendChild(a1Text);
            //Set bs
            Element bsElement = secretKeyDocument.createElement(TAG_SK_BS);
            schemeElement.appendChild(bsElement);
            for (int i=0; i<secretKeyParameters.getBs().length; i++){
                Element biElement = secretKeyDocument.createElement(TAG_SK_BI);
                biElement.setAttribute(CipherParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
                String biString = new String(Hex.encode(secretKeyParameters.getBsAt(i).toBytes()));
                Text biText = secretKeyDocument.createTextNode(biString);
                bsElement.appendChild(biElement);
                biElement.appendChild(biText);
            }
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
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, CipherParameterXMLSerializer.TYPE_CT);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(ciphertextParameters.getLength()));
            ciphertextDocument.appendChild(schemeElement);
            //Set B
            Element bElement = ciphertextDocument.createElement(HIBEBBG05XMLSerializer.TAG_CT_B);
            String bString = new String(Hex.encode(ciphertextParameters.getB().toBytes()));
            Text bText = ciphertextDocument.createTextNode(bString);
            schemeElement.appendChild(bElement);
            bElement.appendChild(bText);
            //Set C
            Element cElement = ciphertextDocument.createElement(HIBEBBG05XMLSerializer.TAG_CT_C);
            String cString = new String(Hex.encode(ciphertextParameters.getC().toBytes()));
            Text cText = ciphertextDocument.createTextNode(cString);
            schemeElement.appendChild(cElement);
            cElement.appendChild(cText);
            return ciphertextDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    public CipherParameters documentDeserialization(PairingParameters pairingParameters, Document document) {
        Element schemeElement = document.getDocumentElement();
        String cipherParameterType = schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_TYPE);
        if (cipherParameterType.equals(CipherParameterXMLSerializer.TYPE_PK)){
            return getInstance().publicKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(CipherParameterXMLSerializer.TYPE_MSK)){
            return getInstance().masterSecretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(CipherParameterXMLSerializer.TYPE_SK)) {
            return getInstance().secretKeyParametersDeserialization(pairingParameters, schemeElement);
        } else if (cipherParameterType.equals(CipherParameterXMLSerializer.TYPE_CT)) {
            return getInstance().ciphertextKeyParametersDeserialization(pairingParameters, schemeElement);
        } else {
            throw new InvalidParameterException("Illegal " + HIBEBBG05Engine.SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxLength = Integer.valueOf(schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_MAX_LENGTH));
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
                    int index = Integer.valueOf(elementHi.getAttribute(CipherParameterXMLSerializer.ATTRI_INDEX));
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
        int length = Integer.valueOf(schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH));
        int maxLength = Integer.valueOf(schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_MAX_LENGTH));
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
                    int index = Integer.valueOf(elementBi.getAttribute(CipherParameterXMLSerializer.ATTRI_INDEX));
                    String biString = elementBi.getFirstChild().getNodeValue();
                    bs[index] = pairing.getG1().newElementFromBytes(Hex.decode(biString)).getImmutable();
                }
            } else if (node.getNodeName().equals(TAG_SK_IDS)) {
                //Set Ids
                NodeList nodeIdsList = ((Element) node).getElementsByTagName(TAG_SK_IDI);
                for (int j=0; j<nodeIdsList.getLength(); j++) {
                    Element elementIdi = (Element)nodeIdsList.item(j);
                    int index = Integer.valueOf(elementIdi.getAttribute(CipherParameterXMLSerializer.ATTRI_INDEX));
                    ids[index] = elementIdi.getFirstChild().getNodeValue();
                }
            }
        }
        elementIds = Utils.MapToZr(pairing, ids);
        return new HIBEBBG05SecretKeyParameters(pairingParameters, ids, elementIds, a0, a1, bs);
    }

    private CipherParameters ciphertextKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH));
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
