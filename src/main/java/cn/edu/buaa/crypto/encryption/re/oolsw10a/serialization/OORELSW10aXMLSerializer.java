package cn.edu.buaa.crypto.encryption.re.oolsw10a.serialization;

import cn.edu.buaa.crypto.SerializationUtils;
import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.CHEngineManager;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.CHKR00Engine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.OORELSW10aEngine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.*;
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
 * Created by Weiran Liu on 16/4/10.
 */
public class OORELSW10aXMLSerializer implements PairingParameterXMLSerializer {
    private static final String TAG_SCHEME_NAME = OORELSW10aEngine.SCHEME_NAME;
    private static final String ATTRI_CH_NAME = "CHName";

    //Tags for public key
    private static final String TAG_PK_G = "G";
    private static final String TAG_PK_Gb = "Gb";
    private static final String TAG_PK_Gb2 = "Gb2";
    private static final String TAG_PK_Hb = "Hb";
    private static final String TAG_PK_EggAlpha = "EggAlpha";
    private static final String TAG_PK_CH = "CHName";

    //Tags for master secret key
    private static final String TAG_MSK_ALPHA = "Alpha";
    private static final String TAG_MSK_B = "b";
    private static final String TAG_MSK_H = "h";

    //Tags for secret key
    private static final String TAG_SK_ID = "id";
    private static final String TAG_SK_D0 = "d0";
    private static final String TAG_SK_D1 = "d1";
    private static final String TAG_SK_D2 = "d2";

    //Tags for intermediate ciphertext
    private static final String TAG_ICT_KEY = "Key";
    private static final String TAG_ICT_C0 = "C0";
    private static final String TAG_ICT_C1S = "C1s";
    private static final String TAG_ICT_C1I = "C1i";
    private static final String TAG_ICT_C2S = "C2s";
    private static final String TAG_ICT_C2I = "C2i";
    private static final String TAG_ICT_CV1 = "Cv1";
    private static final String TAG_ICT_CV2 = "Cv2";
    private static final String TAG_ICT_IS = "Is";
    private static final String TAG_ICT_II = "Ii";
    private static final String TAG_ICT_IV = "Iv";
    private static final String TAG_ICT_SS = "Ss";
    private static final String TAG_ICT_SI = "Si";
    private static final String TAG_ICT_SV = "Sv";
    private static final String TAG_ICT_S = "S";
    private static final String TAG_ICT_CH_SK = "CHSecretKey";
    private static final String TAG_ICT_CH_RES = "CHHashResult";

    //Tags for ciphertext
    private static final String TAG_CT_C0 = "C0";
    private static final String TAG_CT_C1S = "C1s";
    private static final String TAG_CT_C1I = "C1i";
    private static final String TAG_CT_C2S = "C2s";
    private static final String TAG_CT_C2I = "C2i";
    private static final String TAG_CT_CV1 = "Cv1";
    private static final String TAG_CT_CV2 = "Cv2";
    private static final String TAG_CT_IMALLS = "Imalls";
    private static final String TAG_CT_IMALLI = "Imalli";
    private static final String TAG_CT_CH_PK = "CHPublicKey";
    private static final String TAG_CT_CH_RES = "CHHashResult";

    private static final OORELSW10aXMLSerializer INSTANCE = new OORELSW10aXMLSerializer();

    private OORELSW10aXMLSerializer() { }

    public static OORELSW10aXMLSerializer getInstance(){
        return INSTANCE;
    }

    public Document documentSerialization(CipherParameters cipherParameters) {
        if (cipherParameters instanceof OORELSW10aPublicKeyParameters) {
            return getInstance().publicKeyParametersSerialization((OORELSW10aPublicKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof OORELSW10aMasterSecretKeyParameters) {
            return getInstance().masterSecretKeyParametersSerialization((OORELSW10aMasterSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof OORELSW10aSecretKeyParameters) {
            return getInstance().secretKeyParametersSerialization((OORELSW10aSecretKeyParameters) cipherParameters);
        } else if (cipherParameters instanceof OORELSW10aICiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((OORELSW10aICiphertextParameters) cipherParameters);
        } else if (cipherParameters instanceof OORELSW10aCiphertextParameters) {
            return getInstance().ciphertextParametersSerialization((OORELSW10aCiphertextParameters)cipherParameters);
        } else {
            throw new InvalidParameterException("Invalid CipherParameter Instance of " + OORELSW10aEngine.SCHEME_NAME
                    + " Scheme, find" + cipherParameters.getClass().getName());
        }
    }

    private Document publicKeyParametersSerialization(OORELSW10aPublicKeyParameters publicKeyParameters){
        try {
            Document publicKeyParametersDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = publicKeyParametersDocument.createElement(TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_PK);
            publicKeyParametersDocument.appendChild(schemeElement);
            //Set g
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_G, publicKeyParameters.getG());
            //Set gb
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_Gb, publicKeyParameters.getGb());
            //Set gb2
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_Gb2, publicKeyParameters.getGb2());
            //Set hb
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_Hb, publicKeyParameters.getHb());
            //Set eggAlpha
            SerializationUtils.SetElement(publicKeyParametersDocument, schemeElement, TAG_PK_EggAlpha, publicKeyParameters.getEggAlpha());
            //Set CHEngine
            SerializationUtils.SetString(publicKeyParametersDocument, schemeElement, TAG_PK_CH, publicKeyParameters.getCHEngine().getName());
            return publicKeyParametersDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document masterSecretKeyParametersSerialization(OORELSW10aMasterSecretKeyParameters masterSecretKeyParameters) {
        try {
            Document masterSecretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = masterSecretKeyDocument.createElement(OORELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_MSK);
            masterSecretKeyDocument.appendChild(schemeElement);
            //Set alpha
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_ALPHA, masterSecretKeyParameters.getAlpha());
            //Set b
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_B, masterSecretKeyParameters.getB());
            //Set h
            SerializationUtils.SetElement(masterSecretKeyDocument, schemeElement, TAG_MSK_H, masterSecretKeyParameters.getH());
            return masterSecretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document secretKeyParametersSerialization(OORELSW10aSecretKeyParameters secretKeyParameters){
        try {
            Document secretKeyDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = secretKeyDocument.createElement(OORELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_SK);
            secretKeyDocument.appendChild(schemeElement);
            //Set id
            SerializationUtils.SetString(secretKeyDocument, schemeElement, TAG_SK_ID, secretKeyParameters.getId());
            //Set d0
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_D0, secretKeyParameters.getD0());
            //Set d1
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_D1, secretKeyParameters.getD1());
            //Set d2
            SerializationUtils.SetElement(secretKeyDocument, schemeElement, TAG_SK_D2, secretKeyParameters.getD2());
            return secretKeyDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(OORELSW10aICiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(OORELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_ICT);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(ciphertextParameters.getLength()));
            ciphertextDocument.appendChild(schemeElement);
            //Set session key
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_ICT_KEY, ciphertextParameters.getSessionKey());
            //Set C0
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_ICT_C0, ciphertextParameters.getC0());
            //Set C1s
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_ICT_C1S, TAG_ICT_C1I, ciphertextParameters.getC1s());
            //Set C2s
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_ICT_C2S, TAG_ICT_C2I, ciphertextParameters.getC2s());
            //Set Cv1
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_ICT_CV1, ciphertextParameters.getCv1());
            //Set Cv2
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_ICT_CV2, ciphertextParameters.getCv2());
            //Set Is
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_ICT_IS, TAG_ICT_II, ciphertextParameters.getIs());
            //Set Iv
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_ICT_IV, ciphertextParameters.getIv());
            //Set Ss
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_ICT_SS, TAG_ICT_SI, ciphertextParameters.getSs());
            //Set Sv
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_ICT_SV, ciphertextParameters.getSv());
            //Set S
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_ICT_S, ciphertextParameters.getS());
            //Set Chameleon Hash Secret Key
            ChameleonHashSecretKeyParameters chameleonHashSecretKeyParameters = ciphertextParameters.getChameleonHashSecretKey();
            Element chameleonHashSecretKeyElement = ciphertextDocument.createElement(TAG_ICT_CH_SK);
            chameleonHashSecretKeyElement.setAttribute(ATTRI_CH_NAME, chameleonHashSecretKeyParameters.getCHEngineName());
            schemeElement.appendChild(chameleonHashSecretKeyElement);
            ciphertextDocument = CHEngineManager.GetChameleonHashXMLSerializer(chameleonHashSecretKeyParameters.getCHEngineName()).documentSerialization(
                    ciphertextDocument, chameleonHashSecretKeyElement, chameleonHashSecretKeyParameters);
            //Set Chameleon Hash Result
            ChameleonHashResultParameters chameleonHashResultParameters = ciphertextParameters.getChameleonHashResut();
            Element chameleonHashResultElement = ciphertextDocument.createElement(TAG_ICT_CH_RES);
            chameleonHashResultElement.setAttribute(ATTRI_CH_NAME, chameleonHashResultParameters.getCHEngineName());
            schemeElement.appendChild(chameleonHashResultElement);
            ciphertextDocument = CHEngineManager.GetChameleonHashXMLSerializer(chameleonHashResultParameters.getCHEngineName()).documentSerialization(
                    ciphertextDocument, chameleonHashResultElement, chameleonHashResultParameters);
            return ciphertextDocument;
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Document ciphertextParametersSerialization(OORELSW10aCiphertextParameters ciphertextParameters){
        try {
            Document ciphertextDocument = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
            Element schemeElement = ciphertextDocument.createElement(OORELSW10aXMLSerializer.TAG_SCHEME_NAME);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_TYPE, PairingParameterXMLSerializer.TYPE_CT);
            schemeElement.setAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH, Integer.toString(ciphertextParameters.getLength()));
            ciphertextDocument.appendChild(schemeElement);
            //Set C0
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_C0, ciphertextParameters.getC0());
            //Set C1s
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_CT_C1S, TAG_CT_C1I, ciphertextParameters.getC1s());
            //Set C2s
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_CT_C2S, TAG_CT_C2I, ciphertextParameters.getC2s());
            //Set Cv1
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_CV1, ciphertextParameters.getCv1());
            //Set Cv2
            SerializationUtils.SetElement(ciphertextDocument, schemeElement, TAG_CT_CV2, ciphertextParameters.getCv2());
            //Set Imalls
            SerializationUtils.SetElementArray(ciphertextDocument, schemeElement, TAG_CT_IMALLS, TAG_CT_IMALLI, ciphertextParameters.getImalls());
            //Set Chameleon Hash Public Key
            ChameleonHashPublicKeyParameters chameleonHashPublicKeyParameters = ciphertextParameters.getChameleonHashPublicKeyParameters();
            Element chameleonHashPublicKeyElement = ciphertextDocument.createElement(TAG_CT_CH_PK);
            chameleonHashPublicKeyElement.setAttribute(ATTRI_CH_NAME, chameleonHashPublicKeyParameters.getCHEngineName());
            schemeElement.appendChild(chameleonHashPublicKeyElement);
            ciphertextDocument = CHEngineManager.GetChameleonHashXMLSerializer(chameleonHashPublicKeyParameters.getCHEngineName()).documentSerialization(
                    ciphertextDocument, chameleonHashPublicKeyElement, chameleonHashPublicKeyParameters);
            //Set Chameleon Hash Result
            ChameleonHashResultParameters chameleonHashResultParameters = ciphertextParameters.getChameleonHashResultParameters();
            Element chameleonHashResultElement = ciphertextDocument.createElement(TAG_CT_CH_RES);
            chameleonHashResultElement.setAttribute(ATTRI_CH_NAME, chameleonHashResultParameters.getCHEngineName());
            schemeElement.appendChild(chameleonHashResultElement);
            ciphertextDocument = CHEngineManager.GetChameleonHashXMLSerializer(chameleonHashResultParameters.getCHEngineName()).documentSerialization(
                    ciphertextDocument, chameleonHashResultElement, chameleonHashResultParameters);
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
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_ICT)) {
            return getInstance().iCiphertextParametersDeserialization(pairingParameters, document, schemeElement);
        } else if (cipherParameterType.equals(PairingParameterXMLSerializer.TYPE_CT)) {
            return getInstance().ciphertextParametersDeserialization(pairingParameters, document, schemeElement);
        } else {
            throw new InvalidParameterException("Illegal " + OORELSW10aEngine.SCHEME_NAME +
                    " Document Type, find " + cipherParameterType);
        }
    }

    private CipherParameters publicKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element g = null;
        it.unisa.dia.gas.jpbc.Element gb = null;
        it.unisa.dia.gas.jpbc.Element gb2 = null;
        it.unisa.dia.gas.jpbc.Element hb = null;
        it.unisa.dia.gas.jpbc.Element eggAlpha = null;
        String chEngineName;
        CHEngine chEngine = null;
        for (int i=0; i<nodeList.getLength(); i++){
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_PK_G)) {
                //Set g
                g = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_Gb)) {
                //Set gb
                gb = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_Gb2)) {
                //Set gb2
                gb2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_PK_Hb)) {
                //Set hb
                hb = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }else if (node.getNodeName().equals(TAG_PK_EggAlpha)) {
                //Set eggAlpha
                eggAlpha = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.GT);
            } else if (node.getNodeName().equals(TAG_PK_CH)) {
                chEngine = CHEngineManager.GetChameleonHashEngine(SerializationUtils.GetString(node));
            }
        }
        return new OORELSW10aPublicKeyParameters(pairingParameters, g, gb, gb2, hb, eggAlpha, chEngine);
    }

    private CipherParameters masterSecretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element alpha = null;
        it.unisa.dia.gas.jpbc.Element b = null;
        it.unisa.dia.gas.jpbc.Element h = null;
        for (int i=0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_MSK_ALPHA)) {
                //Set alpha
                alpha = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_MSK_B)) {
                b = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_MSK_H)) {
                h = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        return new OORELSW10aMasterSecretKeyParameters(pairingParameters, alpha, b, h);
    }

    private CipherParameters secretKeyParametersDeserialization(PairingParameters pairingParameters, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        NodeList nodeList = schemeElement.getChildNodes();
        String id = null;
        it.unisa.dia.gas.jpbc.Element d0 = null;
        it.unisa.dia.gas.jpbc.Element d1 = null;
        it.unisa.dia.gas.jpbc.Element d2 = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_SK_ID)) {
                id = SerializationUtils.GetString(node);
            } else if (node.getNodeName().equals(TAG_SK_D0)) {
                //Set d0
                d0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_SK_D1)) {
                //Set d1
                d1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_SK_D2)) {
                //Set d2
                d2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            }
        }
        it.unisa.dia.gas.jpbc.Element elementId = PairingUtils.MapToFirstHalfZr(pairing, id);
        return new OORELSW10aSecretKeyParameters(pairingParameters, id, elementId, d0, d1, d2);
    }

    private CipherParameters iCiphertextParametersDeserialization(PairingParameters pairingParameters, Document document, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element sessionKey = null;
        it.unisa.dia.gas.jpbc.Element C0 = null;
        it.unisa.dia.gas.jpbc.Element[] C1s = null;
        it.unisa.dia.gas.jpbc.Element[] C2s = null;
        it.unisa.dia.gas.jpbc.Element Cv1 = null;
        it.unisa.dia.gas.jpbc.Element Cv2 = null;
        it.unisa.dia.gas.jpbc.Element[] Is = null;
        it.unisa.dia.gas.jpbc.Element Iv = null;
        it.unisa.dia.gas.jpbc.Element[] ss = null;
        it.unisa.dia.gas.jpbc.Element sv = null;
        it.unisa.dia.gas.jpbc.Element s = null;
        ChameleonHashSecretKeyParameters chameleonHashSecretKeyParameters = null;
        ChameleonHashResultParameters chameleonHashResultParameters = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_ICT_KEY)) {
                //Set session key
                sessionKey = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.GT);
            } else if (node.getNodeName().equals(TAG_ICT_C0)) {
                //Set C0
                C0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ICT_C1S)) {
                //Set C1s
                C1s = SerializationUtils.GetElementArray(pairing, node, TAG_ICT_C1I, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ICT_C2S)) {
                //Set C2s
                C2s = SerializationUtils.GetElementArray(pairing, node, TAG_ICT_C2I, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ICT_CV1)) {
                //Set Cv1
                Cv1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ICT_CV2)) {
                //Set Cv2
                Cv2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_ICT_IS)) {
                //Set Is
                Is = SerializationUtils.GetElementArray(pairing, node, TAG_ICT_II, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_ICT_IV)) {
                //Set Iv
                Iv = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_ICT_SS)) {
                //Set ss
                ss = SerializationUtils.GetElementArray(pairing, node, TAG_ICT_SI, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_ICT_SV)) {
                //Set sv
                sv = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_ICT_S)) {
                //Set s
                s = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_ICT_CH_SK)) {
                String chEngineName = ((Element)node).getAttribute(ATTRI_CH_NAME);
                chameleonHashSecretKeyParameters = (ChameleonHashSecretKeyParameters) CHEngineManager.
                        GetChameleonHashXMLSerializer(chEngineName).documentDeserialization(pairingParameters, document, (Element)node);
            } else if (node.getNodeName().equals(TAG_ICT_CH_RES)) {
                String chEngineName = ((Element) node).getAttribute(ATTRI_CH_NAME);
                chameleonHashResultParameters = (ChameleonHashResultParameters) CHEngineManager.
                        GetChameleonHashXMLSerializer(chEngineName).documentDeserialization(pairingParameters, document, (Element) node);
            }
        }
        return new OORELSW10aICiphertextParameters(pairingParameters, length,
                C0, C1s, C2s, Cv1, Cv2, Is, Iv, ss, sv, s, sessionKey, chameleonHashSecretKeyParameters, chameleonHashResultParameters);
    }

    private CipherParameters ciphertextParametersDeserialization(PairingParameters pairingParameters, Document document, Element schemeElement) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        int length = Integer.valueOf(schemeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_LENGTH));
        NodeList nodeList = schemeElement.getChildNodes();
        it.unisa.dia.gas.jpbc.Element C0 = null;
        it.unisa.dia.gas.jpbc.Element[] C1s = null;
        it.unisa.dia.gas.jpbc.Element[] C2s = null;
        it.unisa.dia.gas.jpbc.Element Cv1 = null;
        it.unisa.dia.gas.jpbc.Element Cv2 = null;
        it.unisa.dia.gas.jpbc.Element[] Imalls = null;
        ChameleonHashPublicKeyParameters chameleonHashPublicKeyParameters = null;
        ChameleonHashResultParameters chameleonHashResultParameters = null;
        for (int i=0; i<nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeName().equals(TAG_CT_C0)) {
                //Set C0
                C0 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_C1S)) {
                //Set C1s
                C1s = SerializationUtils.GetElementArray(pairing, node, TAG_CT_C1I, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_C2S)) {
                //Set C2s
                C2s = SerializationUtils.GetElementArray(pairing, node, TAG_CT_C2I, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_CV1)) {
                //Set Cv1
                Cv1 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_CV2)) {
                //Set Cv2
                Cv2 = SerializationUtils.GetElement(pairing, node, SerializationUtils.PairingGroupType.G1);
            } else if (node.getNodeName().equals(TAG_CT_IMALLS)) {
                //Set Imalls
                Imalls = SerializationUtils.GetElementArray(pairing, node, TAG_CT_IMALLI, SerializationUtils.PairingGroupType.Zr);
            } else if (node.getNodeName().equals(TAG_CT_CH_PK)) {
            String chEngineName = ((Element)node).getAttribute(ATTRI_CH_NAME);
            chameleonHashPublicKeyParameters = (ChameleonHashPublicKeyParameters) CHEngineManager.
                    GetChameleonHashXMLSerializer(chEngineName).documentDeserialization(pairingParameters, document, (Element)node);
            } else if (node.getNodeName().equals(TAG_CT_CH_RES)) {
                String chEngineName = ((Element) node).getAttribute(ATTRI_CH_NAME);
                chameleonHashResultParameters = (ChameleonHashResultParameters) CHEngineManager.
                    GetChameleonHashXMLSerializer(chEngineName).documentDeserialization(pairingParameters, document, (Element) node);
            }
        }
        return new OORELSW10aCiphertextParameters(pairingParameters ,length, C0, C1s, C2s, Imalls, Cv1, Cv2,
                chameleonHashPublicKeyParameters, chameleonHashResultParameters);
    }
}
