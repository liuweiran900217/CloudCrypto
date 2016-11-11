package cn.edu.buaa.crypto.access.lsss;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.AccessTreeNode;

/**
 * Created by Weiran Liu on 2016/7/18.
 *
 * LSSS policy parameter.
 */
public class LSSSPolicyParameter extends AccessControlParameter {
    //The LSSS matrix
    private int[][] lsssMatrix;
    //number of rows
    private int row;
    //number of columns
    private int column;

    public LSSSPolicyParameter(AccessTreeNode rootAccessTreeNode, int[][] accessPolicy, int[][] lsssMatrix, String[] rhos) {
        super(rootAccessTreeNode, accessPolicy, rhos);
        this.row = lsssMatrix.length;
        this.column = lsssMatrix[0].length;
        this.lsssMatrix = new int[row][column];
        //Copy LSSS Matrix
        for (int i=0; i<this.row; i++) {
            System.arraycopy(lsssMatrix[i], 0, this.lsssMatrix[i], 0, column);
        }
    }

    int getRow() {
        return this.row;
    }

    int getColumn() { return this.column; }

    int[][] getLSSSMatrix(){
        return this.lsssMatrix;
    }

    public String[] getRhos() {
        return this.rhos;
    }

    @Override
    public String toString(){
        StringBuilder buffer = new StringBuilder("M[][], L[i]\n");
        for(int i=0; i<row; i++){
            buffer.append(i).append(" |");
            for(int j=0; j<column; j++){
                buffer.append(lsssMatrix[i][j]).append(",");
            }
            buffer.append("|, Rho[").append(i).append("] = ").append(rhos[i]);
            buffer.append("\n");
        }
        return buffer.toString();
    }
}
