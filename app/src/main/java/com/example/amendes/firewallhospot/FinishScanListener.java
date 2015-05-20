package com.example.amendes.firewallhospot;

import java.util.ArrayList;

/**
 * Created by amendes on 12/05/15.
 */
public interface FinishScanListener {


    /**
     * Interface called when the scan method finishes. Network operations should not execute on UI thread
     * @param  ArrayList of {@link ClientScanResult}
     */

    public void onFinishScan(ArrayList<ClientScanResult> clients);

}