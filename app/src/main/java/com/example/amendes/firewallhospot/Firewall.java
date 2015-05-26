package com.example.amendes.firewallhospot;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;
import android.Manifest;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.widget.Toast;

/**
 * Contains shared programming interfaces.
 * All iptables "communication" is handled by this class.
 */

/**
 * Created by amendes on 18/05/15.
 */
public final class Firewall {

    /**
     * Contains shared programming interfaces.
     * All iptables "communication" is handled by this class.
     *
     * Copyright (C) 2009-2011  Rodrigo Zechin Rosauro
     *
     * This program is free software: you can redistribute it and/or modify
     * it under the terms of the GNU General Public License as published by
     * the Free Software Foundation, either version 3 of the License, or
     * (at your option) any later version.
     *
     * This program is distributed in the hope that it will be useful,
     * but WITHOUT ANY WARRANTY; without even the implied warranty of
     * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     * GNU General Public License for more details.
     *
     * You should have received a copy of the GNU General Public License
     * along with this program.  If not, see <http://www.gnu.org/licenses/>.
     *
     * @author Rodrigo Zechin Rosauro
     * @version 1.0
     */

      

        /** root script filename */
        private static final String SCRIPT_FILE = "firewall.sh";

        // Preferences
        public static final String PREFS_NAME                   = "firewallPrefs";

        public static final String PREF_CUSTOMSCRIPT    = "CustomScript";
        public static final String PREF_CUSTOMSCRIPT2   = "CustomScript2"; // Executed on shutdown
        public static final String PREF_MODE                    = "BlockMode";
        public static final String PREF_ENABLED                 = "Enabled";
        public static final String PREF_LOGENABLED              = "LogEnabled";

        // Modes

        public static final String MODE_WHITELIST = "whitelist";
        public static final String MODE_BLACKLIST = "blacklist";

        // Messages
        public static final String STATUS_CHANGED_MSG   = "com.googlecode.firewall.intent.action.STATUS_CHANGED";
        // Message extras (parameters)
        public static final String STATUS_EXTRA                 = "com.googlecode.firewall.intent.extra.STATUS";


        // Cached applications
        // public static DroidApp applications[] = null;
        // Do we have root access?
        private static boolean hasroot = false;

        /**
         * Display a simple alert box
         * @param ctx context
         * @param msg message
         */
        public static void alert(Context ctx, CharSequence msg) {
            if (ctx != null) {
                new AlertDialog.Builder(ctx)
                        .setNeutralButton(android.R.string.ok, null)
                        .setMessage(msg)
                        .show();
            }
        }

        /**
         * Create the generic shell script header used to determine which iptables binary to use.
         * @param ctx context
         * @return script header
         */
        private static String scriptHeader(Context ctx) {
            final String dir = ctx.getDir("bin",0).getAbsolutePath();
            final String myiptables = dir + "/iptables_armv5";
            return "" +
                    "IPTABLES=iptables\n" +
                    "BUSYBOX=busybox\n" +
                    "GREP=grep\n" +
                    "ECHO=echo\n" + "";
                    /*
                    "# Try to find busybox\n" +
                    "if " + dir + "/busybox_g1 --help >/dev/null 2>/dev/null ; then\n" +
                    "       BUSYBOX="+dir+"/busybox_g1\n" +
                    "       GREP=\"$BUSYBOX grep\"\n" +
                    "       ECHO=\"$BUSYBOX echo\"\n" +
                    "elif busybox --help >/dev/null 2>/dev/null ; then\n" +
                    "       BUSYBOX=busybox\n" +
                    "elif /system/xbin/busybox --help >/dev/null 2>/dev/null ; then\n" +
                    "       BUSYBOX=/system/xbin/busybox\n" +
                    "elif /system/bin/busybox --help >/dev/null 2>/dev/null ; then\n" +
                    "       BUSYBOX=/system/bin/busybox\n" +
                    "fi\n" +
                    "# Try to find grep\n" +
                    "if ! $ECHO 1 | $GREP -q 1 >/dev/null 2>/dev/null ; then\n" +
                    "       if $ECHO 1 | $BUSYBOX grep -q 1 >/dev/null 2>/dev/null ; then\n" +
                    "               GREP=\"$BUSYBOX grep\"\n" +
                    "       fi\n" +
                    "       # Grep is absolutely required\n" +
                    "       if ! $ECHO 1 | $GREP -q 1 >/dev/null 2>/dev/null ; then\n" +
                    "               $ECHO The grep command is required. firewall will not work.\n" +
                    "               exit 1\n" +
                    "       fi\n" +
                    "fi\n" +
                    "# Try to find iptables\n" +
                    "if " + myiptables + " --version >/dev/null 2>/dev/null ; then\n" +
                    "       IPTABLES="+myiptables+"\n" +
                    "fi\n" +
                    "";
                    */

        }

        /**
         * Copies a raw resource file, given its ID to the given location
         * @param ctx context
         * @param resid resource id
         * @param file destination file
         * @param mode file permissions (E.g.: "755")
         * @throws IOException on error
         * @throws InterruptedException when interrupted
         */
        private static void copyRawFile(Context ctx, int resid, File file, String mode) throws IOException, InterruptedException
        {
            final String abspath = file.getAbsolutePath();
            // Write the iptables binary
            final FileOutputStream out = new FileOutputStream(file);
            final InputStream is = ctx.getResources().openRawResource(resid);
            byte buf[] = new byte[1024];
            int len;
            while ((len = is.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            out.close();
            is.close();
            // Change the permissions
            Runtime.getRuntime().exec("chmod "+mode+" "+abspath).waitFor();
        }


        /**
         * Purge and re-add all rules (internal implementation).
         * @param ctx application context (mandatory)
         * @param ip_src ip of source
         * @param ip_dst ip of destiny
         * @param fw_mode if true is whitelist, otherwise blacklist
         * @param flag_all deny all traffic if true
         * @param showErrors indicates if errors should be alerted
         */
        public static boolean applyIptablesRulesImpl(Context ctx, String ip_src, String ip_dst, String port_src, String port_dst
                ,boolean flag_all, boolean fw_mode, boolean showErrors) {
            if (ctx == null) {
                return false;
            }
            assertBinaries(ctx, showErrors);
            final String ITFS_WIFI[] = {"tiwlan+", "wlan+", "eth+", "ra+"};
            final boolean whitelist = fw_mode;
            final boolean logenabled = true;
            final String customScript = "";

            final StringBuilder script = new StringBuilder();
            try {
                int code;
                script.append(scriptHeader(ctx));
                script.append("" +
                        "$IPTABLES --version || exit 1\n" +
                        "# Create the firewall chains if necessary\n" +
                        "$IPTABLES -L firewall >/dev/null 2>/dev/null || $IPTABLES --new firewall || exit 2\n" +
                        "$IPTABLES -L firewall-wifi >/dev/null 2>/dev/null || $IPTABLES --new firewall-wifi || exit 3\n" +
                        "$IPTABLES -L firewall-reject >/dev/null 2>/dev/null || $IPTABLES --new firewall-reject || exit 4\n" +
                        "# Add firewall chain to FORWARD chain if necessary\n" +
                        "$IPTABLES -L FORWARD | $GREP -q firewall || $IPTABLES -A FORWARD -j firewall || exit 5\n" +
                        "# Flush existing rules\n" +
                        //"$IPTABLES -F firewall || exit 6\n" +
                        //"$IPTABLES -F firewall-wifi || exit 7\n" +
                        //"$IPTABLES -F firewall-reject || exit 8\n" +
                        "");
                // Check if logging is enabled
                if (logenabled) {
                    script.append("" +
                            "# Create the log and reject rules (ignore errors on the LOG target just in case it is not available)\n" +
                            "$IPTABLES -A firewall-reject -j LOG --log-prefix \"[firewall] \"\n" +
                            "$IPTABLES -A firewall-reject -j REJECT || exit 9\n" +
                            "");
                } else {
                    script.append("" +
                            "# Create the reject rule (log disabled)\n" +
                            "$IPTABLES -A firewall-reject -j REJECT || exit 10\n" +
                            "");
                }
                if (customScript.length() > 0) {
                    script.append("\n# BEGIN OF CUSTOM SCRIPT (user-defined)\n");
                    script.append(customScript);
                    script.append("\n# END OF CUSTOM SCRIPT (user-defined)\n\n");
                }
                if (whitelist && logenabled) {
                    script.append("# Allow DNS lookups on white-list for a better logging (ignore errors)\n");
                    script.append("$IPTABLES -A firewall -p udp --dport 53 -j RETURN\n");
                }
                script.append("# Main rules (per interface)\n");

                for (final String itf : ITFS_WIFI) {
                    script.append("$IPTABLES -A firewall -i ").append(itf).append(" -j firewall-wifi || exit\n");
                }

                script.append("# Filtering rules\n");

                if (whitelist) {

                    if(flag_all) {
                        /* block any traffic for this ip source */
                        if ((!ip_src.trim().equals("")) && (ip_dst.trim().equals(""))) {
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-s ").append(ip_src + " -j DROP || exit\n");
                        }

                        /* block any traffic for this ip dest */
                        if ((ip_src.trim().equals("")) && (!ip_dst.trim().equals(""))) {
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-s ").append(ip_dst + " -j DROP || exit\n");
                        }
                    } else { // Casos de aplicacao de regras no iptables

                        // Regra cheia

                        if(!ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append("-s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        // Agora regras com destino

                        if(!ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append("-s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(!ip_src.trim().equals("") && !ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-s ").append(ip_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append(" -s ").append(ip_src)
                                    .append(" -j DROP || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" -j DROP || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -s ").append(ip_src)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j DROP || exit\n");
                        }


                        // Agora regras com destino

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -d ").append(ip_dst)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        // Agora so com portas

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" -j DROP || exit\n");
                        }

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j DROP || exit\n");
                        }

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            Toast.makeText(ctx,"Preencha uma das opções!", Toast.LENGTH_LONG).show();
                            return false;
                        }

                    }

                } else {

                    if(flag_all) {
                        /* block any traffic for this ip source */
                        if ((!ip_src.trim().equals("")) && (ip_dst.trim().equals(""))) {
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-s ").append(ip_src + " -j ACCEPT || exit\n");
                        }

                        /* block any traffic for this ip dest */
                        if ((ip_src.trim().equals("")) && (!ip_dst.trim().equals(""))) {
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-s ").append(ip_dst + " -j ACCEPT || exit\n");
                        }
                    } else { // Tornando o firewall em blacklist

                        script.append("$IPTABLES -P INPUT DROP");
                        script.append("$IPTABLES -P FORWARD DROP");
                        script.append("$IPTABLES -P OUTPUT DROP");

                        // Regra cheia

                        if(!ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append("-s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        // Agora regras com destino

                        if(!ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append("-s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(!ip_src.trim().equals("") && !ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-s ").append(ip_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append(" -s ").append(ip_src)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -s ").append(ip_src)
                                    .append(" --sport ").append(port_src)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(!ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -s ").append(ip_src)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }


                        // Agora regras com destino

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" -d ").append(ip_dst)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(ip_src.trim().equals("") && !ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append(" -d ").append(ip_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        // Agora so com portas

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && !port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && !port_src.trim().equals("") && port_dst.trim().equals("")){
                            script.append("$IPTABLES -A firewall-wifi ")
                                    .append("-p tcp ")
                                    .append(" --sport ").append(port_src)
                                    .append(" --dport ").append(port_dst)
                                    .append(" -j ACCEPT || exit\n");
                        }

                        if(ip_src.trim().equals("") && ip_dst.trim().equals("") && port_src.trim().equals("") && port_dst.trim().equals("")){
                            Toast.makeText(ctx,"Preencha uma das opções!", Toast.LENGTH_LONG).show();
                            return false;
                        }
                    }

                }
                final StringBuilder res = new StringBuilder();
                code = runScriptAsRoot(ctx, script.toString(), res);
                if (showErrors && code != 0) {
                    String msg = res.toString();
                    Log.e("firewall", msg);
                    // Remove unnecessary help message from output
                    if (msg.indexOf("\nTry `iptables -h' or 'iptables --help' for more information.") != -1) {
                        msg = msg.replace("\nTry `iptables -h' or 'iptables --help' for more information.", "");
                    }
                    alert(ctx, "Error applying iptables rules. Exit code: " + code + "\n\n" + msg.trim());
                } else {
                    return true;
                }
            } catch (Exception e) {
                if (showErrors) alert(ctx, "error refreshing iptables: " + e);
            }
            return false;
        }

        /**
         * Purge all iptables rules.
         * @param ctx mandatory context
         * @param showErrors indicates if errors should be alerted
         * @return true if the rules were purged
         */
        public static boolean purgeIptables(Context ctx, boolean showErrors) {
            final StringBuilder res = new StringBuilder();
            try {
                assertBinaries(ctx, showErrors);
                // Custom "shutdown" script
                final String customScript = ctx.getSharedPreferences(Firewall.PREFS_NAME, 0).getString(Firewall.PREF_CUSTOMSCRIPT2, "");
                final StringBuilder script = new StringBuilder();
                script.append(scriptHeader(ctx));
                script.append("" +
                        "$IPTABLES -D FORWARD -j firewall\n" +
                        "$IPTABLES -F firewall\n" +
                        "$IPTABLES -F firewall-reject\n" +
                        "$IPTABLES -F firewall-wifi\n" +
                        "");
                if (customScript.length() > 0) {
                    script.append("\n# BEGIN OF CUSTOM SCRIPT (user-defined)\n");
                    script.append(customScript);
                    script.append("\n# END OF CUSTOM SCRIPT (user-defined)\n\n");
                }
                int code = runScriptAsRoot(ctx, script.toString(), res);
                if (code == -1) {
                    if (showErrors) alert(ctx, "Error purging iptables. exit code: " + code + "\n" + res);
                    return false;
                }
                return true;
            } catch (Exception e) {
                if (showErrors) alert(ctx, "Error purging iptables: " + e);
                return false;
            }
        }

        /**
         * Display iptables rules output
         * @param ctx application context
         */
        public static void showIptablesRules(Context ctx) {
            try {
                final StringBuilder res = new StringBuilder();
                runScriptAsRoot(ctx, scriptHeader(ctx) +
                        "$ECHO $IPTABLES\n" +
                        "$IPTABLES -L -v -n\n", res);
                alert(ctx, res);
            } catch (Exception e) {
                alert(ctx, "error: " + e);
            }
        }

        /**
         * Display logs
         * @param ctx application context
         * @return true if the clogs were cleared
         */
        public static boolean clearLog(Context ctx) {
            try {
                final StringBuilder res = new StringBuilder();
                int code = runScriptAsRoot(ctx, "dmesg -c >/dev/null || exit\n", res);
                if (code != 0) {
                    alert(ctx, res);
                    return false;
                }
                return true;
            } catch (Exception e) {
                alert(ctx, "error: " + e);
            }
            return false;
        }

        /**
         * Display logs
         * @param ctx application context
         */

        public static void showLog(Context ctx) {
            try {
                StringBuilder res = new StringBuilder();
                int code = runScriptAsRoot(ctx, scriptHeader(ctx) +
                        "dmesg | $GREP firewall\n", res);
                if (code != 0) {
                    if (res.length() == 0) {
                        res.append("Log is empty");
                    }
                    alert(ctx, res);
                    return;
                }
                final BufferedReader r = new BufferedReader(new StringReader(res.toString()));
                final Integer unknownUID = -99;
                res = new StringBuilder();
                String line;
                int start, end;
                Integer appid;
                final HashMap<Integer, LogInfo> map = new HashMap<Integer, LogInfo>();
                LogInfo loginfo = null;
                while ((line = r.readLine()) != null) {
                    if (line.indexOf("[firewall]") == -1) continue;
                    appid = unknownUID;
                    if (((start=line.indexOf("UID=")) != -1) && ((end=line.indexOf(" ", start)) != -1)) {
                        appid = Integer.parseInt(line.substring(start+4, end));
                    }
                    loginfo = map.get(appid);
                    if (loginfo == null) {
                        loginfo = new LogInfo();
                        map.put(appid, loginfo);
                    }
                    loginfo.totalBlocked += 1;
                    if (((start=line.indexOf("DST=")) != -1) && ((end=line.indexOf(" ", start)) != -1)) {
                        String dst = line.substring(start+4, end);
                        if (loginfo.dstBlocked.containsKey(dst)) {
                            loginfo.dstBlocked.put(dst, loginfo.dstBlocked.get(dst) + 1);
                        } else {
                            loginfo.dstBlocked.put(dst, 1);
                        }
                    }
                }

                /*

                final DroidApp[] apps = getApps(ctx);
                for (Integer id : map.keySet()) {
                    res.append("App ID ");
                    if (id != unknownUID) {
                        res.append(id);
                        for (DroidApp app : apps) {
                            if (app.uid == id) {
                                res.append(" (").append(app.names[0]);
                                if (app.names.length > 1) {
                                    res.append(", ...)");
                                } else {
                                    res.append(")");
                                }
                                break;
                            }
                        }
                    } else {
                        res.append("(kernel)");
                    }
                    loginfo = map.get(id);
                    res.append(" - Blocked ").append(loginfo.totalBlocked).append(" packets");
                    if (loginfo.dstBlocked.size() > 0) {
                        res.append(" (");
                        boolean first = true;
                        for (String dst : loginfo.dstBlocked.keySet()) {
                            if (!first) {
                                res.append(", ");
                            }
                            res.append(loginfo.dstBlocked.get(dst)).append(" packets for ").append(dst);
                            first = false;
                        }
                        res.append(")");
                    }
                    res.append("\n\n");
                }
                */

                if (res.length() == 0) {
                    res.append("Log is empty");
                }
                alert(ctx, res);
            } catch (Exception e) {
                alert(ctx, "error: " + e);
            }
        }

        /**
         * Check if we have root access
         * @param ctx mandatory context
         * @param showErrors indicates if errors should be alerted
         * @return boolean true if we have root
         */
        public static boolean hasRootAccess(Context ctx, boolean showErrors) {
            if (hasroot) return true;
            final StringBuilder res = new StringBuilder();
            try {
                // Run an empty script just to check root access
                if (runScriptAsRoot(ctx, "exit 0", res) == 0) {
                    hasroot = true;
                    return true;
                }
            } catch (Exception e) {
            }
            if (showErrors) {
                alert(ctx, "Could not acquire root access.\n" +
                        "You need a rooted phone to run firewall.\n\n" +
                        "If this phone is already rooted, please make sure firewall has enough permissions to execute the \"su\" command.\n" +
                        "Error message: " + res.toString());
            }
            return false;
        }
        /**
         * Runs a script, wither as root or as a regular user (multiple commands separated by "\n").
         * @param ctx mandatory context
         * @param script the script to be executed
         * @param res the script output response (stdout + stderr)
         * @param timeout timeout in milliseconds (-1 for none)
         * @return the script exit code
         */
        public static int runScript(Context ctx, String script, StringBuilder res, long timeout, boolean asroot) {
            final File file = new File(ctx.getDir("bin",0), SCRIPT_FILE);
            final ScriptRunner runner = new ScriptRunner(file, script, res, asroot);
            runner.start();
            try {
                if (timeout > 0) {
                    runner.join(timeout);
                } else {
                    runner.join();
                }
                if (runner.isAlive()) {
                    // Timed-out
                    runner.interrupt();
                    runner.join(150);
                    runner.destroy();
                    runner.join(50);
                }
            } catch (InterruptedException ex) {}
            return runner.exitcode;
        }
        /**
         * Runs a script as root (multiple commands separated by "\n").
         * @param ctx mandatory context
         * @param script the script to be executed
         * @param res the script output response (stdout + stderr)
         * @param timeout timeout in milliseconds (-1 for none)
         * @return the script exit code
         */
        public static int runScriptAsRoot(Context ctx, String script, StringBuilder res, long timeout) {
            return runScript(ctx, script, res, timeout, true);
        }
        /**
         * Runs a script as root (multiple commands separated by "\n") with a default timeout of 20 seconds.
         * @param ctx mandatory context
         * @param script the script to be executed
         * @param res the script output response (stdout + stderr)
         * @param timeout timeout in milliseconds (-1 for none)
         * @return the script exit code
         * @throws IOException on any error executing the script, or writing it to disk
         */
        public static int runScriptAsRoot(Context ctx, String script, StringBuilder res) throws IOException {
            return runScriptAsRoot(ctx, script, res, 40000);
        }
        /**
         * Runs a script as a regular user (multiple commands separated by "\n") with a default timeout of 20 seconds.
         * @param ctx mandatory context
         * @param script the script to be executed
         * @param res the script output response (stdout + stderr)
         * @param timeout timeout in milliseconds (-1 for none)
         * @return the script exit code
         * @throws IOException on any error executing the script, or writing it to disk
         */
        public static int runScript(Context ctx, String script, StringBuilder res) throws IOException {
            return runScript(ctx, script, res, 40000, false);
        }
        /**
         * Asserts that the binary files are installed in the cache directory.
         * @param ctx context
         * @param showErrors indicates if errors should be alerted
         * @return false if the binary files could not be installed
         */
        public static boolean assertBinaries(Context ctx, boolean showErrors) {
            boolean changed = false;
            try {
                // Check iptables_armv5
                File file = new File(ctx.getDir("bin",0), "iptables_armv5");
                if (!file.exists() || file.length()!=198652) {
                    copyRawFile(ctx, R.raw.iptables_armv5, file, "755");
                    changed = true;
                }
                // Check busybox
                file = new File(ctx.getDir("bin",0), "busybox_g1");
                if (!file.exists()) {
                    copyRawFile(ctx, R.raw.busybox_g1, file, "755");
                    changed = true;
                }
                if (changed) {
                    Toast.makeText(ctx, R.string.toast_bin_installed, Toast.LENGTH_LONG).show();
                }
            } catch (Exception e) {
                if (showErrors) alert(ctx, "Error installing binary files: " + e);
                return false;
            }
            return true;
        }
        /**
         * Check if the firewall is enabled
         * @param ctx mandatory context
         * @return boolean
         */
        public static boolean isEnabled(Context ctx) {
            if (ctx == null) return false;
            return ctx.getSharedPreferences(PREFS_NAME, 0).getBoolean(PREF_ENABLED, false);
        }

        /**
         * Defines if the firewall is enabled and broadcasts the new status
         * @param ctx mandatory context
         * @param enabled enabled flag
         */
        public static void setEnabled(Context ctx, boolean enabled) {
            if (ctx == null) return;
            final SharedPreferences prefs = ctx.getSharedPreferences(PREFS_NAME, 0);
            if (prefs.getBoolean(PREF_ENABLED, false) == enabled) {
                return;
            }
            final Editor edit = prefs.edit();
            edit.putBoolean(PREF_ENABLED, enabled);
            if (!edit.commit()) {
                alert(ctx, "Error writing to preferences");
                return;
            }
                /* notify */
            final Intent message = new Intent(Firewall.STATUS_CHANGED_MSG);
            message.putExtra(Firewall.STATUS_EXTRA, enabled);
            ctx.sendBroadcast(message);
        }

        /**
         * Small internal structure used to hold log information
         */
        private static final class LogInfo {
            private int totalBlocked; // Total number of packets blocked
            private HashMap<String, Integer> dstBlocked; // Number of packets blocked per destination IP address
            private LogInfo() {
                this.dstBlocked = new HashMap<String, Integer>();
            }
        }
        /**
         * Internal thread used to execute scripts (as root or not).
         */
        private static final class ScriptRunner extends Thread {
            private final File file;
            private final String script;
            private final StringBuilder res;
            private final boolean asroot;
            public int exitcode = -1;
            private Process exec;

            /**
             * Creates a new script runner.
             * @param file temporary script file
             * @param script script to run
             * @param res response output
             * @param asroot if true, executes the script as root
             */
            public ScriptRunner(File file, String script, StringBuilder res, boolean asroot) {
                this.file = file;
                this.script = script;
                this.res = res;
                this.asroot = asroot;
            }
            @Override
            public void run() {
                try {
                    file.createNewFile();
                    final String abspath = file.getAbsolutePath();
                    // make sure we have execution permission on the script file
                    Runtime.getRuntime().exec("chmod 777 "+abspath).waitFor();
                    // Write the script to be executed
                    final OutputStreamWriter out = new OutputStreamWriter(new FileOutputStream(file));
                    if (new File("/system/bin/sh").exists()) {
                        out.write("#!/system/bin/sh\n");
                    }
                    out.write(script);
                    if (!script.endsWith("\n")) out.write("\n");
                    out.write("exit\n");
                    out.flush();
                    out.close();
                    if (this.asroot) {
                        // Create the "su" request to run the script
                        exec = Runtime.getRuntime().exec("su -c "+abspath);
                    } else {
                        // Create the "sh" request to run the script
                        exec = Runtime.getRuntime().exec("sh "+abspath);
                    }
                    final InputStream stdout = exec.getInputStream();
                    final InputStream stderr = exec.getErrorStream();
                    final byte buf[] = new byte[8192];
                    int read = 0;
                    while (true) {
                        final Process localexec = exec;
                        if (localexec == null) break;
                        try {
                            // get the process exit code - will raise IllegalThreadStateException if still running
                            this.exitcode = localexec.exitValue();
                        } catch (IllegalThreadStateException ex) {
                            // The process is still running
                        }
                        // Read stdout
                        if (stdout.available() > 0) {
                            read = stdout.read(buf);
                            if (res != null) res.append(new String(buf, 0, read));
                        }
                        // Read stderr
                        if (stderr.available() > 0) {
                            read = stderr.read(buf);
                            if (res != null) res.append(new String(buf, 0, read));
                        }
                        if (this.exitcode != -1) {
                            // finished
                            break;
                        }
                        // Sleep for the next round
                        Thread.sleep(50);
                    }
                } catch (InterruptedException ex) {
                    if (res != null) res.append("\nOperation timed-out");
                } catch (Exception ex) {
                    if (res != null) res.append("\n" + ex);
                } finally {
                    destroy();
                }
            }
            /**
             * Destroy this script runner
             */
            public synchronized void destroy() {
                if (exec != null) exec.destroy();
                exec = null;
            }
        }
    
    
   }
