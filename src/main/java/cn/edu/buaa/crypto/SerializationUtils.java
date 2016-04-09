package cn.edu.buaa.crypto;

import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * Created by liuweiran on 16/4/9.
 */
public class SerializationUtils {
    public static void SetElement(Document document, Element parentElement, String tag, it.unisa.dia.gas.jpbc.Element pairingElement) {
        Element childElement = document.createElement(tag);
        String childString = new String(Hex.encode(pairingElement.toBytes()));
        Text childText = document.createTextNode(childString);
        parentElement.appendChild(childElement);
        childElement.appendChild(childText);
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

    public static void SetStringArray(Document document, Element parentElement, String tag, String indexTag, String[] stringArray) {
        Element childElement = document.createElement(tag);
        parentElement.appendChild(childElement);
        for (int i=0; i<stringArray.length; i++){
            Element childIndexElement = document.createElement(indexTag);
            childIndexElement.setAttribute(PairingParameterXMLSerializer.ATTRI_INDEX, Integer.toString(i));
            Text childIndexText = document.createTextNode(stringArray[i]);
            childElement.appendChild(childIndexElement);
            childIndexElement.appendChild(childIndexText);
        }
    }
}
