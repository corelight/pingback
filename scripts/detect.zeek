module Pingback;

export {
  global payload_lengths: set[count] = {788, 1056};
  global commands: pattern = /upload|download|exe[p,c]|shell/;
  global message_types: set[count] = {1234, 1235, 1236};

  redef enum Notice::Type += { Pingback_Tunnel }; 
}

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string) {
  if (Pingback::commands in payload || |payload| in Pingback::payload_lengths || seq in Pingback::message_types) {
    NOTICE([$note=Pingback::Pingback_Tunnel,
            $conn=c,
            $identifier=cat(c$id$resp_h),
            $msg=fmt("An IMCP ping reply message may have been Pingback")]);
  }
}

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) {
  if (Pingback::commands in payload || |payload| in Pingback::payload_lengths || seq in Pingback::message_types) {
    NOTICE([$note=Pingback::Pingback_Tunnel,
            $conn=c,
            $identifier=cat(c$id$orig_h),
            $msg=fmt("An IMCP ping reply message may have been Pingback")]);
  }
}
