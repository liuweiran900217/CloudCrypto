package cn.edu.buaa.crypto.access;

/**
 * Created by Weiran Liu on 2016/7/19.
 */
public class AccessTreeNode {
    public static AccessTreeNode GenerateAccessTree(final int[][] accessPolicy, final String[] rhos) throws UnsatisfiedAccessControlException {
        return new AccessTreeNode(accessPolicy, 0, rhos);
    }

    private final AccessTreeNode[] childNodes;
    private final int t;
    private final int label;
    private final String attribute;
    private final boolean isLeafNode;

    private AccessTreeNode(final int i, final String rho) {
        this.childNodes = null;
        this.t = 0;
        this.label = i;
        this.isLeafNode = true;
        this.attribute = rho;
    }

    private AccessTreeNode(final int[][] accessPolicy, final int i, final String[] rhos) throws UnsatisfiedAccessControlException {
        int[] accessPolicyNode = accessPolicy[i];
        if (accessPolicyNode[0] < accessPolicyNode[1]) {
            throw new UnsatisfiedAccessControlException("Invalid access policy, n < t in the threahold gate " + i);
        }
        this.childNodes = new AccessTreeNode[accessPolicyNode[0]];
        this.t = accessPolicyNode[1];
        this.label = i;
        this.attribute = null;
        this.isLeafNode = false;
        int k = 0;
        for (int j = 2; j < accessPolicyNode.length; j++) {
            if (accessPolicyNode[j] > 0) {
                this.childNodes[k] = new AccessTreeNode(accessPolicy, accessPolicyNode[j], rhos);
            } else if (accessPolicyNode[j] < 0) {
                this.childNodes[k] = new AccessTreeNode(accessPolicyNode[j], rhos[-accessPolicyNode[j] - 1]);
            } else {
                throw new UnsatisfiedAccessControlException("Invalid access policy, containing access node with index 0");
            }
            k++;
        }
    }

    public boolean isAccessControlSatisfied(final String[] attributes) {
        if (!this.isLeafNode) {
            int satisfiedChildNumber = 0;
            for (int i = 0; i < this.childNodes.length; i++) {
                if (childNodes[i].isAccessControlSatisfied(attributes)) {
                    satisfiedChildNumber++;
                }
            }
            return (satisfiedChildNumber >= t);
        } else {
            for (int i = 0; i < attributes.length; i++) {
                if (this.attribute.equals(attributes[i])) {
                    return true;
                }
            }
            return false;
        }
    }

    public int getT() {
        return this.t;
    }

    public int getN() {
        return this.childNodes.length;
    }

    public AccessTreeNode getChildNodeAt(int index) {
        return this.childNodes[index];
    }

    public boolean isLeafNode() {
        return this.isLeafNode;
    }

    public String getAttribute() {
        return this.attribute;
    }

    public int getLabel() {
        return this.label;
    }
}