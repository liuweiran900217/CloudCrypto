package cn.edu.buaa.crypto.encryption.hibbe.llw16.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.HIBBELLW16Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16SecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16XMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = HIBBELLW16Engine.SCHEME_NAME;

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_G1 = "G1";
    private static final String TAG_PK_G2 = "G2";
    private static final String TAG_PK_G3 = "G3";
    private static final String TAG_PK_US = "Us";
    private static final String TAG_PK_UI = "Ui";


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
    private static final String TAG_CT_C0 = "C0";
    private static final String TAG_CT_C1 = "C1";

    private static final HIBBELLW16XMLSerializer INSTANCE = new HIBBELLW16XMLSerializer();

    private HIBBELLW16XMLSerializer() { }

    public static HIBBELLW16XMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof HIBBELLW16PublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((HIBBELLW16PublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBBELLW16MasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((HIBBELLW16MasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBBELLW16SecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((HIBBELLW16SecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof HIBBELLW16CiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((HIBBELLW16CiphertextParameters) cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + HIBBELLW16Engine.SCHEME_NAME
                    + " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(HIBBELLW16PublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(HIBBELLW16XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_PK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_USER, Integer.toString(publicKeyParameters.getMaxUser()));
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G, publicKeyParameters.getG());
            //Set g1
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G1, publicKeyParameters.getG1());
            //Set g2
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G2, publicKeyParameters.getG2());
            //Set g3
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G3, publicKeyParameters.getG3());
            //Set u
            SerializationUtils.SetElementArray(publicKeyParametersDocument, schemeElement, TAG_PK_US, TAG_PK_UI, publicKeyParameters.getUs());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(HIBBELLW16MasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(HIBBELLW16XMLSerializer.TAG_SCHEME_NAME);
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

    private Document secretKeyParametersSerialization(HIBBELLW16SecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(HIBBELLW16XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_SK);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_MAX_USER, Integer.toString(secretKeyParameters.getBs().length));
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

    private Document ciphertextParametersSerialization(HIBBELLW16CiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(HIBBELLW16XMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_CT);
            ciphertextDocument.appendChild(schemeElement);
            //Set C0
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C0, ciphertextParameters.getC0());
            //Set C1
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C1, ciphertextParameters.getC1());
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
            throw new InvalidParameterException("Illegal " + HIBBELLW16Engine.SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxUser = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_MAX_USER));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element g1 = null;
        it.unisa.dia.gas.jpbc.Element g2 = null;
        it.unisa.dia.gas.jpbc.Element g3 = null;
        it.unisa.dia.gas.jpbc.Element[] us = new it.unisa.dia.gas.jpbc.Element[maxUser];
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
            } else if (node.getNodeName().equals(TAG_PK_US)) {
                //Set us
                NodeList nodeHsList = ((Element) node).getElementsByTagName(TAG_PK_UI);
                for (int j=0; j<nodeHsList.getLength(); j++) {
                    Element elementUi = (Element)nodeHsList.item(j);
                    int index = Integer.valueOf(elementUi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
                    String uiString = elementUi.getFirstChild().getNodeValue();
                    us[index] = pairing.getG1().newElementFromBytes(Hex.decode(uiString)).getImmutable();
                }
            }
        }
        return new HIBBELLW16PublicKeyParameters(pairingParameters, g, g1, g2, g3, us);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g2Alpha = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            //Set g2Alpha
            if (node.getNodeName().equals(TAG_MSK_G2ALPHA)) {
                String g2AlphaString = node.getFirstChild().getNodeValue();
                g2Alpha = pairing.getG1().newElementFromBytes(Hex.decode(g2AlphaString)).getImmutable();
            }
        }
        return new HIBBELLW16MasterSecretKeyParameters(pairingParameters, g2Alpha);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int maxUser = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_MAX_USER));
        NodeList nodeList = schemeElement.getChildNodes();
        String[] ids = null;
        it.unisa.dia.gas.jpbc.Element[] elementIds;
        it.unisa.dia.gas.jpbc.Element a0 = null;
        it.unisa.dia.gas.jpbc.Element a1 = null;
        it.unisa.dia.gas.jpbc.Element[] bs = new it.unisa.dia.gas.jpbc.Element[maxUser];
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
                NodeList nodeBsList = ((Element) node).getElementsByTagName(TAG_SK_BI);
                for (int j=0; j<nodeBsList.getLength(); j++) {
                    Element elementBi = (Element) nodeBsList.item(j);
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
        return new HIBBELLW16SecretKeyParameters(pairingParameters, ids, elementIds, a0, a1, bs);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element C0 = null;
        it.unisa.dia.gas.jpbc.Element C1 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_C0)) {
                //Set C0
                String c0String = node.getFirstChild().getNodeValue();
                C0 = pairing.getG1().newElementFromBytes(Hex.decode(c0String)).getImmutable();
            } else if (node.getNodeName().equals(TAG_CT_C1)) {
                //Set C1
                String c1String = node.getFirstChild().getNodeValue();
                C1 = pairing.getG1().newElementFromBytes(Hex.decode(c1String)).getImmutable();
            }
        }
        return new HIBBELLW16CiphertextParameters(pairingParameters, C0, C1);
    }
}