import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class IDS {
    public static long pktcount = 0;
    public static long totalpktsize = 0;
    public static String [] sinkhole_dns = new String[100];
    public static Map<String, String> arp_s = new HashMap<String, String>();

    static boolean validity (byte [] address) {
        if (address[0] == 10) {
            return true;
        }
        else {
            return false;
        }
    }

    static void sinkhole_lookup() {

        try (BufferedReader br = new BufferedReader(new FileReader("res/sinkholes.txt"))) {
            String line;
            int i = 0;
            while ((line = br.readLine()) != null) {
                sinkhole_dns[i] = line;
                //System.out.println(line);
                i++;
            }
        } catch (FileNotFoundException e) {
            System.out.println("File not found.");
        } catch (IOException e) {
            System.out.println("Error extracting");
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String s) {
                Udp udp = new Udp();
                int s_port = -1, d_port = -1;
                if (packet.hasHeader(udp)) {
                    packet.getHeader(udp);
                    d_port = udp.destination();
                    s_port = udp.source();
                }
                if ((d_port == 53) || (s_port == 53)) {
                    //dns = packet.
                }
            }
        };
    }

    static void unauthorized_access(Pcap pcapfile) {
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String s) {
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                byte[] dIP = new byte[4];
                byte[] sIP = new byte[4];
                int s_port = -1, d_port = -1;
                if (packet.hasHeader(tcp)) {
                    packet.getHeader(tcp);
                    d_port = tcp.destination();
                    s_port = tcp.source();
                }
                if (packet.hasHeader(ip)) {
                    dIP = packet.getHeader(ip).destination();
                    sIP = packet.getHeader(ip).source();
                } else {
                    return;
                }
                String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                String destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

                // Accepting connection from external by sending SYN-ACK
                if (validity(dIP) && !validity(sIP) && tcp.flags_ACK()) {
                    System.out.printf("[Accepted server connection]: rem:%s, srv:%s, port:%d\n", sourceIP, destIP, d_port);
                }
                // Attempting a connection from external server. remote sends ACK
                if (!validity(dIP) && validity(sIP) && tcp.flags_SYN() && tcp.flags_ACK()) {
                    System.out.printf("[Attempted server connection]: rem:%s, srv:%s, port:%d\n", destIP, sourceIP, s_port);
                }
            }
        };
        try {
            pcapfile.loop(Integer.MAX_VALUE, jpacketHandler, "jNetPcap rocks!");
        } finally {
            pcapfile.close();
        }
    }


    static boolean unicode_detector (String req_url) {
        String [] uni = {"%qf", "%25", "%252f", "%%35c","%8s", "%pc", "%%35", "%C1", "%C0", "%AF", "%c1", "%255c", "%63", "%35",
                "%9v", "%c0", "%af", "%1C", "%1c", "%9c", "%9C", "%e0", "%80", "%f0", "%f8", "%fc"};
        for (int i = 0; i < uni.length; i++) {
            if (req_url.contains(uni[i])) {
                return true;
            }
        }
        return false;
    }

    static void IIS_unicode (Pcap pcapfile) {
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String s) {
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                byte[] dIP = new byte[4];
                byte[] sIP = new byte[4];
                int d_port = -1;
                if (packet.hasHeader(tcp)) {
                    d_port = tcp.destination();
                }
                if (packet.hasHeader(ip)) {
                    dIP = packet.getHeader(ip).destination();
                    sIP = packet.getHeader(ip).source();
                } else {
                    return;
                }
                String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                String destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

                Http http = new Http();
                if (packet.hasHeader(tcp) && packet.hasHeader(http))
                    if ((d_port == 80) && !tcp.flags_SYN()) {
                        if (packet.hasHeader(http)) {
                            byte[] payload = http.getPayload();
                            String http_text = payload.toString();
                            final String req_url = http.fieldValue(Http.Request.RequestUrl);
                            if (unicode_detector(req_url)) {
                                System.out.printf("[Unicode IIS exploit]: src:%s, dest:%s\n", sourceIP, destIP);
                            }
                        }
                    }
                }
            };
        try {
            pcapfile.loop(Integer.MAX_VALUE, jpacketHandler, "jNetPcap rocks!");
        } finally {
            pcapfile.close();
        }
    }

    static void spoofed_packets(Pcap pcapfile) {
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String s) {
                Ip4 ip = new Ip4();
                byte[] dIP = new byte[4];
                byte[] sIP = new byte[4];

                if (packet.hasHeader(ip)) {
                    dIP = packet.getHeader(ip).destination();
                    sIP = packet.getHeader(ip).source();
                } else {
                    return;
                }
                String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                String destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                // Validity checker
                if (!validity(sIP) && !validity(dIP)) {
                    System.out.printf("[Spoofed IP address]: src:%s, dest:%s\n", sourceIP, destIP);
                }
            }
        };
        try {
            pcapfile.loop(Integer.MAX_VALUE, jpacketHandler, "jNetPcap rocks!");
        } finally {
//            pcapfile.close();
        }

    }

    static void anomoly_detection(Pcap pcapfile) {
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                pktcount++;
                totalpktsize += packet.getCaptureHeader().wirelen();
            }
        };

        try {
            pcapfile.loop(Integer.MAX_VALUE, jpacketHandler, "jNetPcap rocks!");
        } finally {
            System.out.printf("Analyzed %d packets, %d bytes\n", pktcount, totalpktsize);
            pcapfile.close();
        }
    }

    static void arp_spoofing(Pcap pcapfile) {
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                Arp arp = new Arp();
                byte[] SHA = new byte[4];
                byte[] SPA = new byte[4];

                if (packet.hasHeader(arp)) {
                    SHA = arp.sha();
                    SPA = arp.spa();
                } else {
                    return;
                }
                String SHA_s = org.jnetpcap.packet.format.FormatUtils.mac(SHA);
                String SPA_s = org.jnetpcap.packet.format.FormatUtils.ip(SPA);

                if (arp.operation() == 2) {
                    String value = arp_s.get(SPA_s);
                    if(value == null) {
                        arp_s.put(SPA_s, SHA_s);
                    }
                    else if (!value.equals(SHA_s)) {
                        System.out.printf("[Potential ARP spoofing]: ip:%s, old:%s, new:%s\n", SPA_s, arp_s.get(SPA_s), SHA_s);
                        arp_s.put(SPA_s, SHA_s);
                    }
                }
            }
        };
        try {
            pcapfile.loop(Integer.MAX_VALUE, jpacketHandler, "jNetPcap rocks!");
        } finally {
            pcapfile.close();
        }
    }


    public static void main(String[] args) {
        System.loadLibrary("jnetpcap");

        String fname = "res/samples/q6-unicode.pcap";
        final StringBuilder errbuf = new StringBuilder();
        System.out.println("Opening file for reading: " + fname);

        Pcap pcap = Pcap.openOffline(fname, errbuf);
        if (pcap == null) {
            String msg = errbuf.toString();
            System.out.printf("Error while opening device for capture: " + msg);
            return;
        }
        arp_spoofing(pcap);
        pcap = Pcap.openOffline(fname, errbuf);
//        sinkhole_lookup();
//        pcap = Pcap.openOffline(fname, errbuf);
        unauthorized_access(pcap);
        pcap = Pcap.openOffline(fname, errbuf);
        spoofed_packets(pcap);
        pcap = Pcap.openOffline(fname, errbuf);
        anomoly_detection(pcap);
        pcap = Pcap.openOffline(fname, errbuf);
        IIS_unicode(pcap);

        //   System.out.println("Hello, world!");
    }
}

