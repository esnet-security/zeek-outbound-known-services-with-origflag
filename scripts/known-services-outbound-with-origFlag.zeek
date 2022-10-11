##! This script logs and tracks active services.  For this script, an active
##! service is defined as an IP address and port of a server for which
##! a TCP handshake (SYN+ACK) is observed, assumed to have been done in the
##! past (started seeing packets mid-connection, but the server is actively
##! sending data), or sent at least one UDP packet.
##! If a protocol name is found/known for service, that will be logged,
##! but services whose names can't be determined are also still logged.

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

module KnownOut;

export {
	## The known-services-outbound logging stream identifier.
	redef enum Log::ID += { SERVICES_LOG_OUT };

	## A default logging policy hook for the stream.
	global log_policy_services_out: Log::PolicyHook;

	## The record type which contains the column fields of the known-services
	## log.
	type ServicesInfoOut: Known::ServicesInfo;

	## Event that can be handled to access the :zeek:type:`KnownOut::ServicesInfoOut`
	## record as it is sent on to the logging framework.
	global log_known_services_out: event(rec: ServicesInfoOut);
}

# DOP: I don't think we need this since it's defined by the normal
# known services package
#redef record connection += {
	# This field is to indicate whether or not the processing for detecting
	# and logging the service for this connection is complete.
#	known_services_done: bool &default=F;
#};

# Check if the triplet (host,port_num,service) is already in Known::services
function KnownOut::check(info: ServicesInfoOut) : bool
	{
	if ( [info$host, info$port_num, info$is_local_orig] !in Known::services )
		return F;

	for ( s in info$service )
		{
		if ( s !in Known::services[info$host, info$port_num, info$is_local_orig] )
			return F;
		}
	return T;
	}


event KnownOut::service_info_commit(info: ServicesInfoOut)
	{
	if ( ! Known::use_service_store )
		return;

	local tempservs = info$service;

	for ( s in tempservs )
		{
		local key = Known::AddrPortServTriplet($host = info$host, $p = info$port_num, $serv = s, $orig = info$is_local_orig);
@if ( Version::at_least("5.0") )
		when [info, s, key] ( local r = Broker::put_unique(Known::service_store$store, key,
		                                    T, Known::service_store_expiry) )
			{
@else
                when ( local r = Broker::put_unique(Known::service_store$store, key,
                                                    T, Known::service_store_expiry) )
			{
@endif

			if ( r$status == Broker::SUCCESS )
				{
				if ( r$result as bool ) {
					info$service = set(s);	# log one service at the time if multiservice
					Log::write(KnownOut::SERVICES_LOG_OUT, info);
					}
				}
			else
				Reporter::error(fmt("%s: data store put_unique failure",
				                    Known::service_store_name));
			}
		timeout Known::service_store_timeout
			{
			Log::write(KnownOut::SERVICES_LOG_OUT, info);
			}
		}
	}

event KnownOut::known_service_add(info: ServicesInfoOut)
	{
	if ( Known::use_service_store )
		return;

	if ( KnownOut::check(info) )
		return;

	if ( [info$host, info$port_num, info$is_local_orig] !in Known::services )
		Known::services[info$host, info$port_num, info$is_local_orig] = set();

	 # service to log can be a subset of info$service if some were already seen
	local info_to_log: ServicesInfoOut;
	info_to_log$ts = info$ts;
	info_to_log$host = info$host;
	info_to_log$port_num = info$port_num;
	info_to_log$port_proto = info$port_proto;
	info_to_log$service = set();
	info_to_log$is_local_orig = info$is_local_orig;

	for ( s in info$service )
		{
		if ( s !in Known::services[info$host, info$port_num, info$is_local_orig] )
			{
			add Known::services[info$host, info$port_num, info$is_local_orig][s];
			add info_to_log$service[s];
			}
		}

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(KnownOut::SERVICES_LOG_OUT, info_to_log);
	@endif
	}


event KnownOut::service_info_commit(info: ServicesInfoOut)
	{
	if ( Known::use_service_store )
		return;

	if ( KnownOut::check(info) )
		return;

	local key = cat(info$host, info$port_num, info$is_local_orig);
	Cluster::publish_hrw(Cluster::proxy_pool, key, KnownOut::known_service_add, info);
	event KnownOut::known_service_add(info);
	}

function KnownOut::has_active_service(c: connection): bool
	{
	local proto = get_port_transport_proto(c$id$resp_p);

	switch ( proto ) {
	case tcp:
		# Not a service unless the TCP server did a handshake (SYN+ACK).
		if ( c$resp$state == TCP_ESTABLISHED ||
			 c$resp$state == TCP_CLOSED ||
			 c$resp$state == TCP_PARTIAL ||
		     /h/ in c$history )
			return T;
		return F;
	case udp:
		# Not a service unless UDP server has sent something (or the option
		# to not care about that is set).
		if ( Known::service_udp_requires_response )
			return c$resp$state == UDP_ACTIVE;
		return T;
	case icmp:
		# ICMP is not considered a service.
		return F;
	default:
		# Unknown/other transport not considered a service for now.
		return F;
	}
	}

function KnownOut::known_services_done(c: connection)
	{
	local id = c$id;

	if ( addr_matches_host(id$resp_h, Known::service_tracking) )
		return;

	if ( |c$service| == 1 )
		{
		if ( "ftp-data" in c$service )
			# Don't include ftp data sessions.
			return;

		if ( "DNS" in c$service && c$resp$size == 0 )
			# For dns, require that the server talks.
			return;
		}

	if ( ! KnownOut::has_active_service(c) )
		# If we're here during a analyzer_confirmation, it's still premature
		# to declare there's an actual service, so wait for the connection
		# removal to check again (to get more timely reporting we'd have
		# schedule some recurring event to poll for handshake/activity).
		return;

	c$known_services_done = T;

	# Drop services starting with "-" (confirmed-but-then-violated protocol)
	local tempservs: set[string];
		for (s in c$service)
			if ( s[0] != "-" )
				add tempservs[s];
	
	local local_orig: bool;
	
	if ( c$id$orig_h in Site::local_nets )
		local_orig = T;
	else
		local_orig = F;

	local info = ServicesInfoOut($ts = network_time(), $host = id$resp_h,
	                          $port_num = id$resp_p,
	                          $port_proto = get_port_transport_proto(id$resp_p),
	                          $service = tempservs,
	                          $is_local_orig = local_orig );

	# If no protocol was detected, wait a short time before attempting to log
	# in case a protocol is detected on another connection.
	if ( |c$service| == 0 )
		{
		# Add an empty service so the service loops will work later
		add info$service[""];
		schedule 5min { KnownOut::service_info_commit(info) };
		}
	else
		event KnownOut::service_info_commit(info);
	}

event analyzer_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=-5
	{
	KnownOut::known_services_done(c);
	}

# Handle the connection ending in case no protocol was ever detected.
event connection_state_remove(c: connection) &priority=-5
	{
	if ( c$known_services_done )
		return;

	KnownOut::known_services_done(c);
	}

event zeek_init() &priority=2
	{
	Log::create_stream(KnownOut::SERVICES_LOG_OUT, [$columns=ServicesInfoOut,
	                                         $ev=log_known_services_out,
	                                         $path="known_services_out",
						$policy=log_policy_services_out]);
	}
