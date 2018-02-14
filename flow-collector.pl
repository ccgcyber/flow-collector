#!/usr/bin/perl -w
###############################################################################
# Netflow datagram collector and parser with integration with:
#           NMAP API
#           REPUTATION API
#
###############################################################################
#
###############################################################################

use strict;
use warnings;
use IO qw(Socket);
use Socket;
use Carp;
use POSIX qw(strftime);
use Readonly;
use Sys::Syslog;
use Net::Subnet;
use Mojo::UserAgent;
use English qw(-no_match_vars);

if ( eval { my $io_socket = 'IO::Socket::INET6'; require $io_socket; 1; } ) {
    croak 'Could not load IO::Socket::INET6';
}
if ( eval { my $socket6 = 'Socket6'; require $socket6; 1; } ) {
    croak 'Could not load Socket6';
}
our $VERSION = 1.1;

my $af;

###############################################################################
Readonly my $MILISECONDS_ON_SECOND => 1000;
Readonly my $MINUTES_IN_HOUR       => 60;
Readonly my $HOURS_IN_DAY          => 24;
Readonly my $DAYS_IN_WEEK          => 7;
Readonly my $WEEKS_IN_YEAR         => 52;

Readonly my $IPV4_CODE             => 4;
Readonly my $IPV6_CODE             => 6;

Readonly my $HEADER_NETFLOW_V1     => 16;
Readonly my $SIZE_NETFLOW_V1       => 48;
Readonly my $NETFLOW_V1_CODE       => 1;

Readonly my $HEADER_NETFLOW_V5     => 24;
Readonly my $SIZE_NETFLOW_V5       => 48;
Readonly my $NETFLOW_V5_CODE       => 5;

Readonly my $HEADER_NETFLOW_V9     => 36;
Readonly my $SIZE_NETFLOW_V9       => 48;
Readonly my $NETFLOW_V9_CODE       => 9;

Readonly my $FIFTY_TWO             => 52;

Readonly my $PACKET_PAYLOAD        => 8192;
Readonly my $MAX_FAILURE           => 5;
Readonly my $TCP_CODE              => 6;
############################################################################

sub log_wrapper {
    my $log = shift;

    openlog('FLOW_COLLECTOR', 'ndelay,pid', 'LOG_LOCAL0');
    syslog('LOG_INFO', $log);
    closelog();

    return;
}

sub fuptime {
    my $t = shift;
    my $r = q{};
    my $tmp;

    # Milliseconds
    $tmp = $t % $MILISECONDS_ON_SECOND;
    $r = sprintf '.%03u%s', $tmp, $r;

    # Seconds
    $t   = int( $t / $MILISECONDS_ON_SECOND );
    $tmp = $t % $MINUTES_IN_HOUR;
    $r   = "${tmp}s${r}";

    # Minutes
    $t   = int( $t / $MINUTES_IN_HOUR );
    $tmp = $t % $MINUTES_IN_HOUR;
    if ($tmp) { $r = "${tmp}m${r}"; }

    # Hours
    $t   = int( $t / $MINUTES_IN_HOUR );
    $tmp = $t % $HOURS_IN_DAY;
    if ($tmp) { $r = "${tmp}h${r}"; }

    # Days
    $t   = int( $t / $HOURS_IN_DAY );
    $tmp = $t % $DAYS_IN_WEEK;
    if ($tmp) { $r = "${tmp}d${r}"; }

    # Weeks
    $t   = int( $t / $DAYS_IN_WEEK );
    $tmp = $t % $WEEKS_IN_YEAR;
    if ($tmp) { $r = "${tmp}w${r}"; }

    # Years
    $t = int( $t / $WEEKS_IN_YEAR );
    if ($tmp) { $r = "${tmp}y${r}"; }

    return $r;
}

sub do_listen {
    my $port = shift
      or confess 'No UDP port specified';

    my $socket;

    if ( $af == $IPV4_CODE ) {
        $socket = IO::Socket::INET->new( Proto => 'udp', LocalPort => $port )
          or croak 'Couldn t open UDP4 socket';
    }
    elsif ( $af == $IPV6_CODE ) {
        $socket = IO::Socket::INET6->new( Proto => 'udp', LocalPort => $port )
          or croak 'Couldn t open UDP6 socket';
    }
    else {
        croak 'Unsupported AF';
    }

    return $socket;
}

sub process_nf_v1 {
    my $sender = shift;
    my $pkt    = shift;
    my %header;
    my %flow;
    my $sender_s;

    %header = qw();

    if ( $af == $IPV4_CODE ) { $sender_s = inet_ntoa($sender); }
    if ( $af == $IPV6_CODE ) { $sender_s = inet_ntop( AF_INET6, $sender ); }

    (
        $header{ver},  $header{flows}, $header{uptime},
        $header{secs}, $header{nsecs}
    ) = unpack 'nnNNN', $pkt;

    if (
        length($pkt) <
        ( $HEADER_NETFLOW_V1 + ( $SIZE_NETFLOW_V1 * $header{flows} ) ) )
    {
        my $length = $HEADER_NETFLOW_V1 + ( $SIZE_NETFLOW_V1 * $header{flows} );
        log_wrapper('action=|falha| error=|short_packet_v1| info=|'.length($pkt)
            ." < $length|");
        return;
    }

    my $log = sprintf ' HEADER v.%u (%u flow%s)', $header{ver},
      $header{flows}, $header{flows} == 1 ? q{} : 's';
    log_wrapper("action=|process_header| info=|$log|");

    for ( 0 .. $header{flows} - 1 ) {
        my $off = $HEADER_NETFLOW_V1 + ( $SIZE_NETFLOW_V1 * $_ );
        my $ptr = substr $pkt, $off, $FIFTY_TWO;

        %flow = qw();

        (
            my $src1,
            my $src2,
            my $src3,
            my $src4,
            my $dst1,
            my $dst2,
            my $dst3,
            my $dst4,
            my $nxt1,
            my $nxt2,
            my $nxt3,
            my $nxt4,
            $flow{in_ndx},
            $flow{out_ndx},
            $flow{pkts},
            $flow{bytes},
            $flow{start},
            $flow{finish},
            $flow{src_port},
            $flow{dst_port},
            my $pad1,
            $flow{protocol},
            $flow{tos},
            $flow{tcp_flags}
        ) = unpack 'CCCCCCCCCCCCnnNNNNnnnCCC', $ptr;

        $flow{src} = sprintf '%u.%u.%u.%u', $src1, $src2, $src3, $src4;
        $flow{dst} = sprintf '%u.%u.%u.%u', $dst1, $dst2, $dst3, $dst4;
        $flow{nxt} = sprintf '%u.%u.%u.%u', $nxt1, $nxt2, $nxt3, $nxt4;

        my $flow = sprintf 'from %s started %s finish %s proto %u %s:%u > '
          . '%s:%u %u packets %u octets',
          $sender_s,
          fuptime( $flow{start} ), fuptime( $flow{finish} ),
          $flow{protocol},
          $flow{src}, $flow{src_port}, $flow{dst}, $flow{dst_port},
          $flow{pkts}, $flow{bytes};
        log_wrapper($flow);
    }
    return \%flow;
}

sub process_nf_v5 {
    my $sender = shift;
    my $pkt    = shift;
    my %header;
    my %flow;
    my $sender_s;

    %header = qw();

    if ( $af == $IPV4_CODE ) { $sender_s = inet_ntoa($sender); }
    if ( $af == $IPV6_CODE ) { $sender_s = inet_ntop( AF_INET6, $sender ); }

    (
        $header{ver},  $header{flows}, $header{uptime},
        $header{secs}, $header{nsecs}, $header{flow_seq},
    ) = unpack 'nnNNNN', $pkt;

    if (
        length($pkt) <
        ( $HEADER_NETFLOW_V5 + ( $SIZE_NETFLOW_V5 * $header{flows} ) ) )
    {
        my $length = $HEADER_NETFLOW_V5 + ( $SIZE_NETFLOW_V5 * $header{flows} );
        log_wrapper('action=|falha| error=|short_packet_v5| info=|'.length($pkt)
            ." < $length|");
        return;
    }

    my $log = sprintf ' HEADER v.%u (%u flow%s) seq %u', $header{ver},
      $header{flows}, $header{flows} == 1 ? q{} : 's', $header{flow_seq};
    log_wrapper("action=|process_header| info=|$log|");

    for ( 0 .. $header{flows} - 1 ) {
        my $off = $HEADER_NETFLOW_V5 + ( $SIZE_NETFLOW_V5 * $_ );
        my $ptr = substr $pkt, $off, $FIFTY_TWO;

        %flow = qw();

        (
            my $src1,         my $src2,        my $src3,
            my $src4,         my $dst1,        my $dst2,
            my $dst3,         my $dst4,        my $nxt1,
            my $nxt2,         my $nxt3,        my $nxt4,
            $flow{in_ndx},    $flow{out_ndx},  $flow{pkts},
            $flow{bytes},     $flow{start},    $flow{finish},
            $flow{src_port},  $flow{dst_port}, my $pad1,
            $flow{tcp_flags}, $flow{protocol}, $flow{tos},
            $flow{src_as},    $flow{dst_as},   $flow{src_mask},
            $flow{dst_mask}
        ) = unpack 'CCCCCCCCCCCCnnNNNNnnCCCCnnCC', $ptr;

        $flow{src} = sprintf '%u.%u.%u.%u', $src1, $src2, $src3, $src4;
        $flow{dst} = sprintf '%u.%u.%u.%u', $dst1, $dst2, $dst3, $dst4;
        $flow{nxt} = sprintf '%u.%u.%u.%u', $nxt1, $nxt2, $nxt3, $nxt4;

        my $log_ = sprintf 'from %s started %s finish %s proto %u %s:%u > ' .
            '%s:%u %u %u packets %u octets',
            $sender_s,
            fuptime($flow{start}), fuptime($flow{finish}),
            $flow{protocol},
            $flow{src}, $flow{src_port}, $flow{dst}, $flow{dst_port},
            $flow{pkts}, $flow{bytes}, $flow{tcp_flags};
        log_wrapper($log_);

        verify_reputation(\%flow);
    }
    return;
}

sub process_nf_v9 {
}

sub verify_reputation {
    my $flow = shift;

    my $src = $flow->{src};
    my $srcp = $flow->{src_port};
    my $dst = $flow->{dst};
    my $dstp = $flow->{dst_port};
    my $flags = $flow->{tcp_flags};
    my $proto = $flow->{protocol};

    if ($proto == $TCP_CODE) {
        if ( $flow->{tcp_flags} ) { # Looking packages with flags
            log_wrapper("action=|verify_reputation| phase=|phase1| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp| flags=|$flags|");

            my @network = split / /, $ENV{FLOW_CONNECTOR_NETWORK};
            my $classif_network = subnet_matcher(@network);

            if ( $classif_network->($src) ) { # INSIDE CONNECTIONS OUT
                my @dst_trusted = split / /, $ENV{FLOW_CONNECTOR_DST_TRUSTED};
                my $classif_dst_trusted = subnet_matcher(@dst_trusted);

                # DIFFERENT DESTINATIONS
                if ( $classif_dst_trusted->($dst) ) {
                    log_wrapper("action=|verify_reputation| phase=|discarded| info=|dst_trustworthy| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;

                # KNOWN OR SUSPENDED DESTINATIONS
                } elsif ( reputation($dst) =~ /malicious/ ) {
                    my $reputation = submit_reputation($src,'infected','scan');
                    my $flow_result = submit_flow($flow,'infected','scan');
                    log_wrapper("action=|set_infected| info=|dst_malicious| result_reputation=|$reputation| result_flow=|$flow_result| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;
                } elsif ( reputation($dst) =~ /suspicious/ ) {
                    my $reputation = submit_reputation($src,'infected','scan');
                    my $flow_result = submit_flow($flow,'infected','scan');
                    log_wrapper("action=|set_infected| info=|dst_suspicious| result_reputation=|$reputation| result_flow=|$flow_result| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;
                }

            } elsif ( $classif_network->($dst) ) { # CONNECTIONS FROM OUT TO
                my @src_trusted = split / /, $ENV{FLOW_CONNECTOR_SRC_TRUSTED};
                my $classif_src_trusted = subnet_matcher(@src_trusted);

                my @honeypots = split / /, $ENV{FLOW_CONNECTOR_HONEYPOTS};
                my $classif_honeypots = subnet_matcher(@honeypots);

                my @darknet = split / /, $ENV{FLOW_CONNECTOR_DARKNET};
                my $classif_darnet = subnet_matcher(@darknet);

                # TRUE ORIGINS
                if ( $classif_src_trusted->($src) ) {
                    log_wrapper("action=|verify_reputation| phase=|discarded| info=|src_trustworthy| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;
                    
                # MALICIOUS DESTINATIONS (HONEYPOTS)
                } elsif ( $classif_honeypots->($dst) ) {
                    my $reputation = submit_reputation($src,'malicious','honeypot');
                    my $flow_result = submit_flow($flow,'malicious','honeypot');
                    log_wrapper("action=|set_malicious| info=|dst_honeypot| result_reputation=|$reputation| result_flow=|$flow_result| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;

                # MALICIOUS DESTINATIONS (DARKNET)
                } elsif ( ! $classif_darnet->($dst) ) {
                    my $reputation = submit_reputation($src,'malicious','darknet');
                    my $flow_result = submit_flow($flow,'malicious','darknet');
                    log_wrapper("action=|set_malicious| info=|dst_darknet| result_reputation=|$reputation| result_flow=|$flow_result| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;

                # DESTINATIONS WITHOUT SERVICE
                } elsif ( is_mapped($dst,$dstp) eq 'NOT_OK') {
                    my $reputation = submit_reputation($src,'suspicious','scan');
                    my $flow_result = submit_flow($flow,'malicious','scan');
                    log_wrapper("action=|set_suspicious| info=|dst_not_mapped| result_reputation=|$reputation| result_flow=|$flow_result| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;

                # KNOWN OR SUSPICIOUS ORIGINS
                } elsif ( reputation($src) =~ /malicious/ ) {
                    my $reputation = submit_reputation($src,'malicious','scan');
                    my $flow_result = submit_flow($flow,'malicious','scan');
                    log_wrapper("action=|set_malicious| info=|src_malicious| result_reputation=|$reputation| result_flow=|$flow_result| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;
                } elsif ( reputation($src) =~ /suspicious/ ) {
                    my $reputation = submit_reputation($src,'suspicious','scan');
                    my $flow_result = submit_flow($flow,'malicious','scan');
                    log_wrapper("action=|set_suspicious| info=|src_suspicious| result_reputation=|$reputation| result_flow=|$flow_result| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                    return;
                }

            } else { # FALSE CONNECTIONS
                log_wrapper("action=|alert| info=|possible_ip_spoofing| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp|");
                return;
            }

        } else {
            log_wrapper("action=|verify_reputation| phase=|discarded| info=|no_it_has_flags| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp| flags=|$flags|");
            return;
        }
    } else {
        log_wrapper("action=|verify_reputation| phase=|discarded| info=|no_tcp| src=|$src| srcp=|$srcp| dst=|$dst| dstp=|$dstp| proto=|$proto");
        return;
    }
}

sub is_mapped {
    my $ip = shift;
    my $port  = shift;

    my $ua = Mojo::UserAgent->new;
    if ($ua->get("$ENV{FLOW_CONNECTOR_NMAP_API_PROTOCOL}://$ENV{FLOW_CONNECTOR_NMAP_API_USER}:$ENV{FLOW_CONNECTOR_NMAP_API_PASS}\@$ENV{FLOW_CONNECTOR_NMAP_API_HOST}:$ENV{FLOW_CONNECTOR_NMAP_API_PORT}/api/1.0/net/$ip/32?port=$port")->res->body =~ '"status":"up"') {
        return 'OK';
    } else {
        return 'NOT_OK';
    }
}

sub reputation {
    my $ip = shift;

    my $ua = Mojo::UserAgent->new;
    my $body = $ua->get("$ENV{FLOW_CONNECTOR_REPUTATION_API_PROTOCOL}://$ENV{FLOW_CONNECTOR_REPUTATION_API_USER}:$ENV{FLOW_CONNECTOR_REPUTATION_API_PASS}\@$ENV{FLOW_CONNECTOR_REPUTATION_API_HOST}:$ENV{FLOW_CONNECTOR_REPUTATION_API_PORT}/api/1.0/ip/$ip")->res->body;
    if ($body =~ '"status":"malicious"') {
        return 'malicious';
    } elsif ($body =~ '"status":"suspicious"') {
        return 'suspicious';
    } elsif ($body =~ '"result":"error"') {
        return 'error';
    }

    return 'error';
}

sub submit_reputation {
    my $ip = shift;
    my $status = shift;
    my $detection = shift;

    my $ua = Mojo::UserAgent->new;
    if ($ua->put("$ENV{FLOW_CONNECTOR_REPUTATION_API_PROTOCOL}://$ENV{FLOW_CONNECTOR_REPUTATION_API_USER}:$ENV{FLOW_CONNECTOR_REPUTATION_API_PASS}\@$ENV{FLOW_CONNECTOR_REPUTATION_API_HOST}:$ENV{FLOW_CONNECTOR_REPUTATION_API_PORT}/api/1.0/ip/$ip?status=$status&detection=$detection")->res->body =~ '"result":"success"') {
        return 'OK';
    } else {
        return 'NOT_OK';
    }
}

sub submit_flow {
    my $flow = shift;
    my $status = shift;
    my $detection = shift;

    my $ua = Mojo::UserAgent->new;
    if ($ua->put("$ENV{FLOW_CONNECTOR_REPUTATION_API_PROTOCOL}://$ENV{FLOW_CONNECTOR_REPUTATION_API_USER}:$ENV{FLOW_CONNECTOR_REPUTATION_API_PASS}\@$ENV{FLOW_CONNECTOR_REPUTATION_API_HOST}:$ENV{FLOW_CONNECTOR_REPUTATION_API_PORT}/api/1.0/flow/body?status=$status&detection=$detection" => {DNT => 1} => json => $flow)->res->body =~ '"result":"success"') {
        return 'OK';
    } else {
        return 'NOT_OK';
    }
}
############################################################################

# Commandline options

my $af4  = 0;
my $af6  = 0;
my $port = $ENV{FLOW_COLLECTOR_PORT};
log_wrapper("action=|init_main| port=|$ENV{FLOW_COLLECTOR_PORT}|".
    " ipcode=|$ENV{FLOW_COLLECTOR_IPTYPE}| logtype=|LOCAL|");

if ( $ENV{FLOW_COLLECTOR_IPTYPE} eq 'IPV4' ) { $af4 = $af = $IPV4_CODE; }
if ( $ENV{FLOW_COLLECTOR_IPTYPE} eq 'IPV6' ) { $af6 = $af = $IPV6_CODE; }

# Unbuffer output
$OUTPUT_AUTOFLUSH = 1;    #ok

# Main loop - receive and process a packet
while (1) {

    my $socket;
    my $from;
    my $payload;
    my $ver;
    my $failcount = 0;
    my $junk;
    my $sender;

    # Open the listening port if we haven't already
    if ( !defined $socket ) { $socket = do_listen( $port, $af ); }

    # Fetch a packet
    $from = $socket->recv( $payload, $PACKET_PAYLOAD, 0 );

    if ($af4) { ( $junk, $sender ) = unpack_sockaddr_in($from); }
    if ($af6) { ( $junk, $sender ) = unpack_sockaddr_in6($from); }

    # Reopen listening socket on error
    if ( !defined $from ) {
        $socket->close;
        undef $socket;

        $failcount++;
        if ( $failcount > $MAX_FAILURE ) {
            log_wrapper('action=|falha| error=|max_failure| info=|Couldn t recv packet|');
        }
        next;    # Socket will be reopened at start of loop
    }

    if ( length($payload) < $HEADER_NETFLOW_V1 ) {
        log_wrapper('action=|falha| error=|short_packet| info=|'.length($payload).
            " < $HEADER_NETFLOW_V1|");
        next;
    }

    # The version is always the first 16 bits of the packet
    ($ver) = unpack 'n', $payload;

    if ( $ver == $NETFLOW_V1_CODE ) { process_nf_v1( $sender, $payload ); }
    elsif ( $ver == $NETFLOW_V5_CODE ) { process_nf_v5( $sender, $payload ); }
    elsif ( $ver == $NETFLOW_V9_CODE ) { process_nf_v9( $sender, $payload ); }
    else {
        log_wrapper ("action=|falha| info=|Unsupported netflow version $ver|");
        next;
    }

    undef $payload;
    next;
}

exit 0;
