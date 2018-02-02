
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class Firewall {

    final static int MAXPORT = 65535;
    public ArrayList<ArrayList<String>> rules = new ArrayList<>(MAXPORT*4);


    public Firewall(String filepath){
        //to ensure size of arraylist
        for(int i = 0; i < MAXPORT*4; i++){
            rules.add(new ArrayList<String>());
        }
        String csvFile =  filepath;
        BufferedReader br = null;
        String line = "";
        String cvsSplitBy = ",";

        try {

            br = new BufferedReader(new FileReader(csvFile));
            while ((line = br.readLine()) != null) {
                // use comma as separator
                String[] rule = line.split(cvsSplitBy);
                if(rule[0].equals("outbound")){
                    if(rule[1].equals("tcp")){
                        if(rule[2].contains("-")){
                            String[] range = rule[2].split("-");
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for(int i = start; i <= end; i++){
                                rules.get(i).add(rule[3]);
                            }
                        }
                        else{
                            int index = Integer.parseInt(rule[2]);
                            if(rules.get(index).isEmpty()){
                                rules.add(index, new ArrayList<String>());
                                rules.get(index).add(rule[3]);
                            }
                            else{
                                rules.get(index).add(rule[3]);
                            }
                        }
                    }
                    else{
                        if(rule[2].contains("-")){
                            String[] range = rule[2].split("-");
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for(int i = start; i <= end; i++){
                                rules.get(i).add(rule[3]);
                            }
                        }
                        else{
                            int index = Integer.parseInt(rule[2]) + MAXPORT;
                            if(rules.get(index).isEmpty()){
                                rules.add(index, new ArrayList<String>());
                                rules.get(index).add(rule[3]);
                            }
                            else{
                                rules.get(index).add(rule[3]);
                            }
                        }

                    }

                }
                else{
                    if(rule[1].equals("tcp")){
                        if(rule[2].contains("-")){
                            String[] range = rule[2].split("-");
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for(int i = start; i <= end; i++){
                                rules.get(i).add(rule[3]);
                            }
                        }
                        else{
                            int index = Integer.parseInt(rule[2]) + MAXPORT*2;
                            if(rules.get(index).isEmpty()){
                                rules.add(index, new ArrayList<String>());
                                rules.get(index).add(rule[3]);

                            }
                            else{
                                System.out.println(index);
                                rules.get(index).add(rule[3]);
                            }
                        }

                    }
                    else{
                        if(rule[2].contains("-")){
                            String[] range = rule[2].split("-");
                            int start = Integer.parseInt(range[0]);
                            int end = Integer.parseInt(range[1]);
                            for(int i = start; i <= end; i++){
                                rules.get(i).add(rule[3]);
                            }

                        }
                        else{
                            int index = Integer.parseInt(rule[2]) + MAXPORT*3;
                            if(rules.get(index).isEmpty()){
                                rules.add(index, new ArrayList<String>());
                                rules.get(index).add(rule[3]);

                            }
                            else{
                                rules.get(index).add(rule[3]);
                            }
                        }
                    }

                }
            }


        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }


    public boolean accept_packet(String direction, String protocol, int port, String ip_address) throws UnknownHostException{
        int startIndex = 0;

        if (direction.equals("outbound") && protocol.equals("tcp")){
            startIndex = 0;
        }
        if (direction.equals("outbound") && protocol.equals("udp")){
            startIndex += MAXPORT;
        }
        else if (direction.equals("inbound") && protocol.equals("tcp")){
            startIndex += MAXPORT*2;
        }
        else if (direction.equals("inbound") && protocol.equals("udp")){
            startIndex += MAXPORT*3;
        }

        return lookup(startIndex, port, ip_address);
    }

    public boolean lookup(int startIndex, int port, String ip_address) throws UnknownHostException{
        ArrayList<String> possibleIPs = rules.get(startIndex+port);
        for(String ip : possibleIPs){
            if(ip.contains("-")){
                String[] range = ip.split("-");
                if(ipToLong(InetAddress.getByName(ip_address)) <= ipToLong(InetAddress.getByName(range[1])) && ipToLong(InetAddress.getByName(ip_address)) >= ipToLong(InetAddress.getByName(range[0]))){
                    return true;
                }
            }
            else if(ip.equals(ip_address)) {
                return true;
            }
        }
        return false;
    }

    public static long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }
}
