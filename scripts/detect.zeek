module Pingback;

export {
  global payload_lengths: set[count] = {788, 1056};
  global commands: pattern = /^upload|^download|^exep|^shell|^rexec/;
  global message_types: set[count] = {53764, 54020, 54276}; 

  redef enum Notice::Type += { Pingback_Tunnel }; 
}

# 'any' is used here for info because this could be an icmp_info or icmp_conn
# depending on the zeek version. since it is only used in a fmt("%s") statement
# the specific type is not important.
event icmp_echo_reply(c: connection, info: any, id: count, seq: count, payload: string) {
    if ( seq in Pingback::message_types && |payload| in Pingback::payload_lengths && Pingback::commands in payload ) 
    {
        NOTICE([$note=Pingback::Pingback_Tunnel,
            $conn=c,
            $identifier=cat(c$id$resp_h),
            $msg=fmt("An ICMP ping reply message may have been Pingback C2 ref:trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/"),
            $sub=fmt("seq=%s , |payload|=%s , icmp_info=%s , first 20 bytes of ICMP payload=%s",seq,|payload|,info,sub_bytes(payload,0,20))]);
    }
}
event icmp_echo_request(c: connection, info: any, id: count, seq: count, payload: string) {
    if ( seq in Pingback::message_types && |payload| in Pingback::payload_lengths && Pingback::commands in payload ) 
    {
        NOTICE([$note=Pingback::Pingback_Tunnel,
            $conn=c,
            $identifier=cat(c$id$orig_h),
            $msg=fmt("An ICMP ping request message may have been Pingback C2 ref:trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/" ),
            $sub=fmt("seq=%s , |payload|=%s , icmp_info=%s , first 20 bytes of ICMP payload=%s",seq,|payload|,info,sub_bytes(payload,0,20))]);
    }
}
