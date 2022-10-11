# Built-in known services conflicts with known-services-with-origFlag
@unload protocols/conn/known-services
@load site/zeek-known-services-with-origFlag
@load ./known-services-outbound-with-origFlag.zeek
