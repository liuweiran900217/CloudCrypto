package cn.edu.buaa.crypto;

import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.*;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.*;
import org.w3c.dom.Element;

/**
 * Created by Weiran Liu on 16/4/9.
 *
 * XML serialization utilties.
 */
public class SerializationUtils {
    public enum PairingGroupType {
        Zr, G1, G2, GT,
    }

    public static void SetElement(Document document, Element parentElement, String tag, it.unisa.dia.gas.jpbc.Element pairingElement) {
        Element childElement = document.createElement(tag);
        String childString = new String(Hex.encode(pairingElement.toBytes()));
        Text childText = document.createTextNode(childString);
        parentElement.appendChild(childElement);
        childElement.appendChild(childText);
    }

    public static it.unisa.dia.gas.jpbc.Element GetElement(Pairing pairing, Node node, PairingGroupType type) {
        String nodeString = node.getFirstChild().getNodeValue();
        switch (type) {
            case G1: return pairing.getG1().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
            case G2: return pairing.getG2().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
            case GT: return pairing.getGT().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
            case Zr: return pairing.getZr().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
            default: throw new IllegalArgumentException("Do not exist the given group type for element deserialization");
        }
    }

    public static it.unisa.dia.gas.jpbc.Element[] GetElementArray(Pairing pairing, Node node,
                                                                  String indexTag, PairingGroupType type) {
        NodeList nodeList = ((Element) node).getElementsByTagName(indexTag);
        it.unisa.dia.gas.jpbc.Element[] nodeElements = new it.unisa.dia.gas.jpbc.Element[nodeList.getLength()];
        for (int j=0; j<nodeList.getLength(); j++) {
            Element nodeElement = (Element) nodeList.item(j);
            int index = Integer.valueOf(nodeElement.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
            String nodeString = nodeElement.getFirstChild().getNodeValue();
            switch (type) {
                case G1:
                    nodeElements[index] = pairing.getG1().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
                    break;
                case G2:
                    nodeElements[index] = pairing.getG2().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
                    break;
                case GT:
                    nodeElements[index] = pairing.getGT().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
                    break;
                case Zr:
                    nodeElements[index] = pairing.getZr().newElementFromBytes(Hex.decode(nodeString)).getImmutable();
                    break;
                default:
                    throw new IllegalArgumentException("Do not exist the given group type for element deserialization");
            }
        }
        return nodeElements;
    }

    public static void SetElementArray(Document document, Element parentElement,
                                       String tag, String indexTag, it.unisa.dia.gas.jpbc.Element[] pairingElementArray) {
        Element childElement = document.createElement(tag);
        parentElement.appendChild(childElement);
        for (int i=0; i<pairingElementArray.length; i++){
            Element childIndexElement = document.createElement(indexTag);
            childIndexElement.setAttribute(PairingParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
            String childIndexString = new String(Hex.encode(pairingElementArray[i].toBytes()));
            Text childIndexText = document.createTextNode(childIndexString);
            childElement.appendChild(childIndexElement);
            childIndexElement.appendChild(childIndexText);
        }
    }

    public static void SetString(Document document, Element parentElement, String tag, String string) {
        Element childElement = document.createElement(tag);
        Text childText = document.createTextNode(string);
        parentElement.appendChild(childElement);
        childElement.appendChild(childText);
    }

    public static String GetString(Node node) {
        return node.getFirstChild().getNodeValue();
    }

    public static void SetStringArray(Document document, Element parentElement, String tag, String indexTag, String[] stringArray) {
        Element childElement = document.createElement(tag);
        parentElement.appendChild(childElement);
        for (int i=0; i<stringArray.length; i++){
            Element childIndexElement = document.createElement(indexTag);
            childIndexElement.setAttribute(PairingParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
            if (stringArray[i] != null) {
                Text childIndexText = document.createTextNode(stringArray[i]);
                childElement.appendChild(childIndexElement);
                childIndexElement.appendChild(childIndexText);
            } else {
                Text childIndexText = document.createTextNode("");
                childElement.appendChild(childIndexElement);
                childIndexElement.appendChild(childIndexText);
            }
        }
    }

    public static String[] GetStringArray(Node node, String indexTag) {
        NodeList nodeIdsList = ((Element) node).getElementsByTagName(indexTag);
        String[] stringArray = new String[nodeIdsList.getLength()];
        for (int j=0; j<nodeIdsList.getLength(); j++) {
            Element elementIdi = (Element)nodeIdsList.item(j);
            int index = Integer.valueOf(elementIdi.getAttribute(PairingParameterXMLSerializer.ATTRI_INDEX));
            if (elementIdi.hasChildNodes()) {
                stringArray[index] = elementIdi.getFirstChild().getNodeValue();
            }
        }
        return stringArray;
    }

    public static void SetIntArray(Document document, Element parentElement, String tag, int[] intArray) {
        Element childElement = document.createElement(tag);
        parentElement.appendChild(childElement);
        for (int i=0; i<intArray.length; i++) {
            Element childIndexElement = document.createElement(Integer.toString(i));
            Text childIndexText = document.createTextNode(Integer.toString(intArray[i]));
            childElement.appendChild(childIndexElement);
            childIndexElement.appendChild(childIndexText);
        }
    }

    public static void SetInt2DArray(Document document, Element parentElement, String tag, int[][] int2DArray) {
        Element childElement = document.createElement(tag);
        parentElement.appendChild(childElement);
        for (int i=0; i<int2DArray.length; i++) {
            SetIntArray(document, parentElement, Integer.toString(i), int2DArray[i]);
        }
    }
}
