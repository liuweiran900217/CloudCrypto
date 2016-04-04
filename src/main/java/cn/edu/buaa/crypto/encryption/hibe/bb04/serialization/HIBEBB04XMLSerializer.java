package cn.edu.buaa.crypto.encryption.hibe.bb04.serialization;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04SecretKeyParameters;
import cn.edu.buaa.crypto.serialization.CipherParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.*;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 15-10-2.
 */
public class HIBEBB04XMLSerializer implements CipherParameterXMLSerializer {
    private static final String TAG_SCHEME = HIBEBB04Engine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_G1 = "G1";
    private static final String TAG_PK_G2 = "G2";
    private static final String TAG_PK_HS = "Hs";
    private static final String TAG_PK_HI = "Hi";

    //Tags for master secret key
    private static final String TAG_MSK_G2ALPHA = "G2Alpha";

    //Tags for secret key
    private static final String TAG_SK_D0 = "d0";
    private static final String TAG_SK_DS = "ds";
    private static final String TAG_SK_DI = "di";
    private static final String TAG_SK_IDS = "Ids";
    private static final String TAG_SK_IDI = "idi";

    //Tags for ciphertexts
    private static final String TAG_CT_B = "B";
    private static final String TAG_CT_CS = "Cs";
    private static final String TAG_CT_CI = "Ci";

    private static final HIBEBB04XMLSerializer INSTANCE = new HIBEBB04XMLSerializer();

    private HIBEBB04XMLSerializer() { }

    public static HIBEBB04XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof HIBEBB04PublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((HIBEBB04PublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBB04MasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((HIBEBB04MasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBB04SecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((HIBEBB04SecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBEBB04CiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((HIBEBB04CiphertextParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of HIBEBB04Engine Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(HIBEBB04PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_PK);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(publicKeyParameters.getMaxLength()));
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

    private Document masterSecretKeyParametersSerialization(HIBEBB04MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_MSK);
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

    private Document secretKeyParametersSerialization(HIBEBB04SecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_SK);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(secretKeyParameters.getLength()));
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
            //Set d0
            Element d0Element = secretKeyDocument.createElement(HIBEBB04XMLSerializer.TAG_SK_D0);
            String D0String = new String(Hex.encode(secretKeyParameters.getD0().toBytes()));
            Text d0Text = secretKeyDocument.createTextNode(D0String);
            schemeElement.appendChild(d0Element);
            d0Element.appendChild(d0Text);
            //Set ds
            Element dsElement = secretKeyDocument.createElement(TAG_SK_DS);
            schemeElement.appendChild(dsElement);
            for (int i=0; i<secretKeyParameters.getLength(); i++){
                Element diElement = secretKeyDocument.createElement(TAG_SK_DI);
                diElement.setAttribute(CipherParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
                String diString = new String(Hex.encode(secretKeyParameters.getDsAt(i).toBytes()));
                Text diText = secretKeyDocument.createTextNode(diString);
                dsElement.appendChild(diElement);
                diElement.appendChild(diText);
            }
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(HIBEBB04CiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(HIBEBB04XMLSerializer.TAG_SCHEME);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_TYPE, HIBEBB04XMLSerializer.TYPE_CT);
            schemeElement.setAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(ciphertextParameters.getLength()));
            ciphertextDocument.appendChild(schemeElement);
            //Set B
            Element bElement = ciphertextDocument.createElement(HIBEBB04XMLSerializer.TAG_CT_B);
            String bString = new String(Hex.encode(ciphertextParameters.getB().toBytes()));
            Text bText = ciphertextDocument.createTextNode(bString);
            schemeElement.appendChild(bElement);
            bElement.appendChild(bText);
            //Set Cs
            Element csElement = ciphertextDocument.createElement(TAG_CT_CS);
            schemeElement.appendChild(csElement);
            for (int i=0; i<ciphertextParameters.getLength(); i++){
                Element ciElement = ciphertextDocument.createElement(TAG_CT_CI);
                ciElement.setAttribute(CipherParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
                String ciString = new String(Hex.encode(ciphertextParameters.getCsAt(i).toBytes()));
                Text ciText = ciphertextDocument.createTextNode(ciString);
                csElement.appendChild(ciElement);
                ciElement.appendChild(ciText);
            }
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
            return getInstance().ciphertextParametersDeserialization(pairingParameters, schemeElement);
        } else {
            throw new InvalidParameterException("Illegal HIBEBB04Engine Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxLength = Integer.valueOf(schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element g1 = null;
        it.unisa.dia.gas.jpbc.Element g2 = null;
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
        return new HIBEBB04PublicKeyParameters(pairingParameters, g, g1, g2, hs);
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
        return new HIBEBB04MasterSecretKeyParameters(pairingParameters, g2Alpha);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        String[] ids = new String[length];
        it.unisa.dia.gas.jpbc.Element[] elementIds = new it.unisa.dia.gas.jpbc.Element[length];
        it.unisa.dia.gas.jpbc.Element d0 = null;
        it.unisa.dia.gas.jpbc.Element[] ds = new it.unisa.dia.gas.jpbc.Element[length];
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_D0)) {
                //Set d0
                String d0String = node.getFirstChild().getNodeValue();
                d0 = pairing.getG1().newElementFromBytes(Hex.decode(d0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_SK_DS)) {
                //Set ds
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_SK_DI);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementDi = (Element) nodeHsList.item(j);
                    int index = Integer.valueOf(elementDi.getAttribute(CipherParameterXMLSerializer.ATTRI_INDEX));
                    String diString = elementDi.getFirstChild().getNodeValue();
                    ds[index] = pairing.getG1().newElementFromBytes(Hex.decode(diString)).getImmutable();
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
        return new HIBEBB04SecretKeyParameters(pairingParameters, ids, elementIds, d0, ds);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(CipherParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element B = null;
        it.unisa.dia.gas.jpbc.Element[] Cs = new it.unisa.dia.gas.jpbc.Element[length];
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_B)) {
                //Set B
                String bString = node.getFirstChild().getNodeValue();
                B = pairing.getG1().newElementFromBytes(Hex.decode(bString)).getImmutable();
            } else if (node.getNodeName().equals(TAG_CT_CS)) {
                //Set Cs
                NodeList nodeCsList = ((Element) node).getElementsByTagName(TAG_CT_CI);
                for (int j=0; j<nodeCsList.getLength(); j++) {
                    Element elementCi = (Element) nodeCsList.item(j);
                    int index = Integer.valueOf(elementCi.getAttribute(CipherParameterXMLSerializer.ATTRI_INDEX));
                    String ciString = elementCi.getFirstChild().getNodeValue();
                    Cs[index] = pairing.getG1().newElementFromBytes(Hex.decode(ciString)).getImmutable();
                }
            }
        }
        return new HIBEBB04CiphertextParameters(pairingParameters, length, B, Cs);
    }
}
