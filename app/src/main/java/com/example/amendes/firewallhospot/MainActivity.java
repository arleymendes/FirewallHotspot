package com.example.amendes.firewallhospot;


import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Handler;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.SimpleAdapter;
import android.widget.TabHost;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class MainActivity extends ActionBarActivity {

    private String checado = "OFF";
    private TextView textView1;
    private WifiApManager wifiApManager;
    private ToggleButton tg1;
    private TabHost tb;
    private CheckBox chk;
    private EditText ssid;
    private EditText presharedkey;
    private Map<String, String> datum;
    private ArrayList<String[]> devices;
    private final Handler h = new Handler();
    private final int delay = 3000; //milliseconds
    private ListView listview;
    private WifiManager wifimanager;
    private Method[] methods;
    private Firewall fw;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.firewall_tab_main);


        chk = (CheckBox)findViewById(R.id.TFCHKBox);
        ssid = (EditText)findViewById(R.id.TFSSID);
        presharedkey = (EditText)findViewById(R.id.TFPSK);
        tg1 = (ToggleButton)findViewById(R.id.TFButton);
        textView1 = (TextView)findViewById(R.id.TFStatusText);
        devices = new ArrayList<String[]>();
        fw = new Firewall();

        tb = (TabHost)findViewById(R.id.tabHost);

        tb.setup();

        TabHost.TabSpec spec = tb.newTabSpec("tab1");
        spec.setContent(R.id.tab1);
        spec.setIndicator("HOTSPOT");
        tb.addTab(spec);

        spec = tb.newTabSpec("tab2");
        spec.setContent(R.id.tab2);
        spec.setIndicator("FIREWALL");
        tb.addTab(spec);

        spec = tb.newTabSpec("tab3");
        spec.setContent(R.id.tab3);
        spec.setIndicator("LOG");
        tb.addTab(spec);

        listview = (ListView)findViewById(R.id.TFListClients);
        listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {

            @Override
            public void onItemClick(AdapterView<?> arg0, View arg1,
                                    int position, long arg3) {

                // ListView Clicked item value
                int i = 0;
                for (String[]temp: devices){
                    if (i == position){
                        // Show Alert
                        Toast.makeText(getApplicationContext(),
                                "DEVICE: " + temp[0] + "\n" + "MAC: " + temp[1], Toast.LENGTH_LONG)
                                .show();
                        break;
                    }
                    i++;
                }
                //devices.clear();
            }
        });

        wifiApManager = new WifiApManager(this);

        if(wifiApManager.isWifiApEnabled()){
            tg1.setChecked(true);
            this.displayCurrentWifiConfig();
        }

        this.updateStateWifiClients();
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            fw.purgeIptables(MainActivity.this,true,true);
            MainActivity.this.finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void scan() {

        wifiApManager.getClientList(false, new FinishScanListener() {

            @Override
            public void onFinishScan(final ArrayList<ClientScanResult> clients) {

                textView1.setText("Status: " + wifiApManager.getWifiApState());

                if (!clients.isEmpty()){

                    List<Map<String, String>> data = new ArrayList<Map<String, String>>();
                    Map<String, String> datum = new HashMap<String, String>(2);
                    for (ClientScanResult clientScanResult : clients) {

                        datum.put("IPADDR", "IP: " + clientScanResult.getIpAddr());
                        datum.put("CONNECT", "Status: " + (clientScanResult.isReachable()?"online":"offline"));
                        data.add(datum);

                        SimpleAdapter adapter = new SimpleAdapter(MainActivity.this, data,
                                android.R.layout.simple_list_item_2,
                                new String[] {"IPADDR", "CONNECT"},
                                new int[] {android.R.id.text1,
                                        android.R.id.text2});
                        listview.setAdapter(adapter);

                        // Guardando os demais dados do dispositivo
                        String[]tmp = new String[2];
                        tmp[0] = clientScanResult.getDevice();
                        tmp[1] = clientScanResult.getHWAddr();
                        devices.add(tmp);
                    }
                    data.clear();
                    datum.clear();
                    //clients_antigo = clients;

                }else{
                    if(checado.equals("OFF")){
                        listview.setAdapter(null);
                    }
                }
            }
        });
    }

    public void activateWifi(WifiApManager w, WifiConfiguration t){
        try {

            if (w.setWifiApConfiguration(t)) {

                //Habilita o hotspot wifi

                wifiApManager.setWifiApEnabled(wifiApManager.getWifiApConfiguration(), true);
                Toast.makeText(MainActivity.this, "Hotspot ativado", Toast.LENGTH_SHORT).show();
                checado = "ON";
                this.updateStateWifiClients();

            }

        } catch (Exception e) {
            Log.e(this.getClass().toString(), "", e);
        }

    }

    public void displayCurrentWifiConfig(){

        wifimanager = (WifiManager) getSystemService(WIFI_SERVICE);
        methods = wifimanager.getClass().getDeclaredMethods();
        for (Method m : methods) {
            if (m.getName().equals("getWifiApConfiguration")) {
                WifiConfiguration config = null;
                try {
                    config = (WifiConfiguration) m.invoke(wifimanager);
                    ssid.setText(config.SSID);
                    presharedkey.setText(config.preSharedKey);
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                } catch (InvocationTargetException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void updateStateWifiClients(){

        //Realiza a atualizacao da tela a cada 3 segundos

        h.postDelayed(new Runnable() {
            public void run() {
                scan();
                h.postDelayed(this, delay);
            }
        }, delay);

    }

    public void onSwitchChange(View wifi) {

        // Pegando os parâmetros de configuração do Hot SpotWifi e setando o Wifi

        if (wifi.getId() == R.id.TFButton) {

            String networkssid = ssid.getText().toString();
            String networkpass = presharedkey.getText().toString();

            //Cria o objeto de configuração do Hotspot customizado

            WifiConfiguration tmp = wifiApManager.setWifiConfiguration(networkssid.trim(), networkpass.trim(), chk.isChecked());

            //Valida os campos. Se SSID e PreSharedKey vazios, a configuração default passa a ser utilizada

            if (networkssid.trim().equals("") && networkpass.trim().equals("")) {

                if (!wifiApManager.isWifiApEnabled() && !checado.equals(tg1.getText().toString())) {

                    //Ativa o paramêtros default de Hotspot do Equipamento

                    this.activateWifi(wifiApManager,tmp);
                    this.displayCurrentWifiConfig();

                    return;

                } else {
                    if (networkssid.trim().equals("")) {
                        Toast.makeText(MainActivity.this, "Coloque o nome do SSID", Toast.LENGTH_SHORT).show();
                        if (!checado.equals(tg1.getText())) {
                            tg1.setChecked(checado.equals("ON"));
                        }
                        return;
                    }
                    if (networkpass.trim().equals("") || networkpass.length() < 8) {
                        Toast.makeText(MainActivity.this, "Chave de acesso em branco ou com tamanho inferior a 8 caracteres", Toast.LENGTH_SHORT).show();
                        if (!checado.equals(tg1.getText())) {
                            tg1.setChecked(checado.equals("ON"));
                        }
                        return;
                    }
                }
            }

            // Aplica a configuração colocada nos campos

            if (!wifiApManager.isWifiApEnabled() && !checado.equals(tg1.getText().toString())){
                this.activateWifi(wifiApManager,tmp);
            } else {
                    tg1.setChecked(false);
                    checado = "OFF";
                    wifiApManager.setWifiApEnabled(wifiApManager.getWifiApConfiguration(), false);
                    Toast.makeText(MainActivity.this, "Hotspot desativado", Toast.LENGTH_SHORT).show();
            }

        }
    }

    public void onClickFwApply(View fwapply){

        if (fwapply.getId() == R.id.TFButtonFw){

            EditText origem = (EditText)findViewById(R.id.TFFwSrc);
            EditText prtorigem = (EditText)findViewById(R.id.TFFwPtSrc);
            EditText destino = (EditText)findViewById(R.id.TFFwDst);
            EditText prtdestino = (EditText)findViewById(R.id.TFFwPtDst);
            CheckBox denyall = (CheckBox)findViewById(R.id.TFFwChkDenyall);

            String src = origem.getText().toString();
            String prtsrc = prtorigem.getText().toString();
            String dst = destino.getText().toString();
            String prtdst = prtdestino.getText().toString();
            Boolean deny = denyall.isChecked();

            if(fw.applyIptablesRulesImpl(MainActivity.this,src,dst,prtsrc,prtdst,deny,true,true)){
                origem.setText("");
                prtorigem.setText("");
                destino.setText("");
                prtdestino.setText("");
                denyall.setChecked(false);
                Toast.makeText(MainActivity.this, "Regra aplicada com sucesso", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, "Falha na aplicação da regra", Toast.LENGTH_SHORT).show();
            }

        }

    }

    public void onClickShowRules(View rules){
        if(rules.getId() == R.id.TFBtnShowRules){
            fw.showIptablesRules(MainActivity.this);
        }
    }

    public void onClickPurgeWifiRules(View purge){
        if (purge.getId() == R.id.TFBtnPurgeWifiRules){
            if(fw.purgeIptables(MainActivity.this,true,false)){
                Toast.makeText(MainActivity.this, "Rules Wifi deletadas", Toast.LENGTH_SHORT).show();
            }
        }
    }

}