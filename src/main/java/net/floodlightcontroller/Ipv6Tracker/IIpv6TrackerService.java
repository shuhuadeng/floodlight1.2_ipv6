package net.floodlightcontroller.Ipv6Tracker;

import java.util.Map;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IIpv6TrackerService extends IFloodlightService{

	/**
	 * 获得正常主机的IPV6，MAC地址
	 * @return
	 */
	public Map<String,String> getMacIpv6();
	
	public Map<String, String> getHost();
}
