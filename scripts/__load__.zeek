# Built-in known services conflicts with known-services-with-origFlag
@unload protocols/conn/known-services
@load site/Zeek-Known-Services-With-OrigFlag
@load ./known-services-outbound-with-origFlag.zeek
