package net.floodlightcontroller.Ipv6Tracker;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.Ipv6Tracker.web.Ipv6TrackerWebRoutable;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.restserver.IRestApiService;

public class Ipv6Tracker implements IFloodlightModule, IOFMessageListener, IIpv6TrackerService {


	protected IFloodlightProviderService floodlightProvider;
	protected IDeviceService deviceService;
	protected IRestApiService restApi;
	protected Map<String,String> macIpv6;
	protected Set<String> macAddresses;
	protected static Logger logger;
	protected static List<IpProtocol> exitHeader;
	String sourceMac;
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		  return Ipv6Tracker.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return (type.equals(OFType.PACKET_IN) && name.equalsIgnoreCase("devicemanager"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && name.equalsIgnoreCase("forwarding"));
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		switch (msg.getType()) {
		
		case PACKET_IN:
			return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);
		default:
			break;
		}
		return Command.CONTINUE;
	}

	private net.floodlightcontroller.core.IListener.Command processPacketInMessage(IOFSwitch sw, OFPacketIn msg,
			FloodlightContext cntx) {
		// TODO Auto-generated method stub
		 Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                 IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		/* Long sourceMACHash = eth.getSourceMACAddress().getLong();
		 if (!macAddresses.contains(sourceMACHash)) {
			 macAddresses.add(sourceMACHash);
			 logger.info("MAC Address: {} seen on switch: {}",
					 eth.getSourceMACAddress().toString(),
					 sw.getId().toString());
		 }*/
		 if(eth.getEtherType() == EthType.IPv6){
			 
				IPv6 ipv6 = (IPv6) eth.getPayload();	
		        InetAddress srcIP = ipv6.getSourceAddress().toInetAddress();
				InetAddress dstIP = ipv6.getDestinationAddress().toInetAddress();
				logger.info("src_ip {},-------> dst_IP {}",srcIP,dstIP);
				//扩展首部攻击——路由提示攻击（扩展首部为60）
		        if(IpProtocol.IPv6_OPTS == ipv6.getNextHeader()) {
		        	logger.info("扩展首部攻击---路由提示攻击！～");
		        	return Command.STOP;
		        }
		        //扩展首部攻击——未知首部攻击
		        if(!exitHeader.contains(ipv6.getNextHeader())) {
		        	logger.info("扩展首部攻击---未知首部攻击！～");
		        	return Command.STOP;
		        }
				//重复地址检测
				if(ipv6.getNextHeader()==IpProtocol.IPv6_ICMP){
		        //	System.out.println(ipv6.toString());
		        	byte [] data = ipv6.getPayload().serialize();
		            int type = data[0]&0xff;
		            switch(type){
		         /*     case 1:   System.out.println("ICMPv6 type is Destination Unreachable! ");
		                case 2:   System.out.println("ICMPv6 type is Packet Too Big! ");
		                case 3:   System.out.println("ICMPv6 type is Time Exceeded! ");
		                case 4:   System.out.println("ICMPv6 type is Parameter Problem! ");
		                case 100: System.out.println("ICMPv6 type is Private experimentation! ");
		                case 101: System.out.println("ICMPv6 type is Private experimentation! ");
		                case 127: System.out.println("ICMPv6 type is Reserved for expansion of ICMPv6 error messages! ");
		            	case 128: System.out.println("ICMPv6 type is Ehco Request! ");
		            	case 129: System.out.println("ICMPv6 type is Ehco Reply! ");
		            	case 130: System.out.println("ICMPv6 type is Multicast Listener Query! ");
		            	case 131: System.out.println("ICMPv6 type is Multicast Listener Report! ");
		            	case 132: System.out.println("ICMPv6 type is Multicast Listener Done! ");*/
		            	case 128: 
		            		System.out.println("ICMPv6 type is Ehco Request! ");
		            		break;
		            	case 129: 
		            		System.out.println("ICMPv6 type is Ehco Reply! ");
		            		break;
		            	case 133: 
		            		System.out.println("ICMPv6 type is Router Solication! ");
		            		for(IDevice device: deviceService.getAllDevices()) {
		            			String mac = device.getMACAddressString();
		            			if(!macIpv6.containsKey(mac)) {
		            				if(device.getIPv6Addresses().length >0) {
		            					String value = device.getIPv6Addresses()[0].toInetAddress().toString();
			            				macIpv6.put(mac, value);
		            				}
		        
		            			}
		            		}
		            	    break;
		            	case 134: 
		            		System.out.println("ICMPv6 type is Router Advertisement! ");
		            		break;
		            	case 135: 
		            		System.out.println("ICMPv6 type is Neighbor Solication! ");
		            		sourceMac = eth.getSourceMACAddress().toString();
					/*
					 * System.out.println(sourceMac); for(String key: macIpv6.keySet()) {
					 * if(key.contains(sourceMac.substring(9, 16))) { sourceMac = key; } }
					 * System.out.println(sourceMac);
					 */
		            		break; 
		            	case 136: 
		            		System.out.println("ICMPv6 type is Neighbor Advertisement! ");
		            		int flag = 0;
		            		for(String key:macIpv6.keySet()) {
		            			if(!macIpv6.get(key).equalsIgnoreCase(srcIP.toString())) {
		            				flag++;
		            			}
		            		}
		                    //消息是伪造的，丢弃该消息
		            		if(flag == macIpv6.size()) {
		            			macAddresses.add(sourceMac);
		            			logger.info("Forged NA！！！Drop!!!");
		            			return Command.STOP;
		            		} 
		            		break;
		           	/*	case 137: System.out.println("ICMPv6 type is Redirect Message! ");
		            	case 138: System.out.println("ICMPv6 type is Router Renumbering! ");
		            	case 139: System.out.println("ICMPv6 type is ICMP Node Information Query! ");
		            	case 140: System.out.println("ICMPv6 type is ICMP Node Information Response! ");
		            	case 141: System.out.println("ICMPv6 type is Inverse Neighbor Discovery Solicitation Message! ");
		            	case 142: System.out.println("ICMPv6 type is Inverse Neighbor Discovery Advertisement Message! ");
		            	case 143: System.out.println("ICMPv6 type is Version 2 Multicast Listener Report! ");
		            	case 144: System.out.println("ICMPv6 type is Home Agent Address Discovery Request Message! ");
		            	case 145: System.out.println("ICMPv6 type is Home Agent Address Discovery Reply Message! ");
		            	case 146: System.out.println("ICMPv6 type is Mobile Prefix Solicitation! ");
		            	case 147: System.out.println("ICMPv6 type is Mobile Prefix Advertisement! ");
		            	case 148: System.out.println("ICMPv6 type is Certification Path Solicitation Message! ");
		            	case 149: System.out.println("ICMPv6 type is Certification Path Advertisement Message! ");
		            	case 150: System.out.println("ICMPv6 type is ICMP messages utilized by experimental! ");
		            	case 151: System.out.println("ICMPv6 type is Multicast Router Advertisement! ");
		            	case 152: System.out.println("ICMPv6 type is Multicast Router Solicitation! ");
		            	case 153: System.out.println("ICMPv6 type is Multicast Router Termination! ");
		            	case 154: System.out.println("ICMPv6 type is FMIPv6 Messages! ");
		            	case 200: System.out.println("ICMPv6 type is Private experimentation! ");
		            	case 201: System.out.println("ICMPv6 type is Private experimentation ! ");
		            	case 255: System.out.println("ICMPv6 type is Reserved for expansion of ICMPv6 informational! ");*/
		            }
		        }
		 }
		 return Command.CONTINUE;
		}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>(); 
		l.add(IIpv6TrackerService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>(); 
		m.put(IIpv6TrackerService.class,this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		  Collection<Class<? extends IFloodlightService>> l =
			        new ArrayList<Class<? extends IFloodlightService>>();
			    l.add(IFloodlightProviderService.class);
			    l.add(IRestApiService.class); 
			    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub

		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        deviceService = context.getServiceImpl(IDeviceService.class);
		macAddresses = new ConcurrentSkipListSet<String>();
		logger = LoggerFactory.getLogger(Ipv6Tracker.class);
		macIpv6 = new HashMap<String, String>();
		restApi = context.getServiceImpl(IRestApiService.class); 
		exitHeader = new ArrayList<IpProtocol>();
		Init(exitHeader);
	}

	/**
	 * 初始化已存在的IPV6扩展首部
	 * @param exitHeader
	 */
	private void Init(List<IpProtocol> exitHeader) {
		exitHeader.add(IpProtocol.HOPOPT);
		exitHeader.add(IpProtocol.TCP);
		exitHeader.add(IpProtocol.UDP);
		exitHeader.add(IpProtocol.IPv6_ROUTE);
		exitHeader.add(IpProtocol.IPv6_FRAG);
		exitHeader.add(IpProtocol.ESP);
		exitHeader.add(IpProtocol.AH);
		exitHeader.add(IpProtocol.IPv6_ICMP);
		exitHeader.add(IpProtocol.IPv6_NO_NXT);
		exitHeader.add(IpProtocol.IPv6_OPTS);
		exitHeader.add(IpProtocol.EIGRP);
		exitHeader.add(IpProtocol.OSPF);
		exitHeader.add(IpProtocol.PIM);
		exitHeader.add(IpProtocol.MOBILITY_HEADER);
		exitHeader.add(IpProtocol.MOBILITY_HEADER);
		exitHeader.add(IpProtocol.L2TP);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new Ipv6TrackerWebRoutable());
	}

	@Override
	public Map<String, String> getMacIpv6() {
		return macIpv6;
	}

	@Override
	public Map<String, String> getHost() {
		Map<String,String> host = new HashMap<>();
		for(String s: macAddresses) {
			host.put("MAC",s);
			host.put("IPV6",macIpv6.get(s));
			for(IDevice device: deviceService.getAllDevices()) {
				String mac = device.getMACAddressString();
				if(s!=null && s.equalsIgnoreCase(mac)) {
					SwitchPort []sws =  device.getAttachmentPoints();
					if(sws.length>0) {
						host.put("switch",sws[0].getNodeId().toString());
						host.put("switchPort",sws[0].getPortId().toString());
					}
				}
			}
			
		}
		return host;
	}
	
	
}
