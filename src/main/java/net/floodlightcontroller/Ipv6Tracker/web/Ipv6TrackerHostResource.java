package net.floodlightcontroller.Ipv6Tracker.web;

import java.util.HashMap;
import java.util.Map;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import net.floodlightcontroller.Ipv6Tracker.IIpv6TrackerService;

public class Ipv6TrackerHostResource extends ServerResource{

	@Get("json")
	public Map<String, String> retrieve(){
		IIpv6TrackerService ipv6TrackerService =  (IIpv6TrackerService) getContext().getAttributes().
				get(IIpv6TrackerService.class.getCanonicalName());
		Map<String, String> host = new HashMap<>();
		host = ipv6TrackerService.getHost();
		return host;
		
	}
}
