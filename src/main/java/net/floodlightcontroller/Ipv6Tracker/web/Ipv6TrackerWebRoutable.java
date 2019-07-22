package net.floodlightcontroller.Ipv6Tracker.web;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class Ipv6TrackerWebRoutable implements RestletRoutable{

	@Override
	public Restlet getRestlet(Context context) {
		Router router = new Router(context);
		router.attach("/ipv6/json",Ipv6TrackerResource.class);
		router.attach("/host/json",Ipv6TrackerHostResource.class);
		return router;
	}

	@Override
	public String basePath() {
		return "/wm/ipv6Tracker";
	}

}
