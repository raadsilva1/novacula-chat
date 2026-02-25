#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha1);
use JSON::PP ();
use Getopt::Long qw(GetOptions);

my $host   = '127.0.0.1';
my $port   = 39007;
my $token  = '';
my $post_userfb = '';
my $post_comment = '';
my $do_subscribe = 1;

GetOptions(
  'host=s'      => \$host,
  'port=i'      => \$port,
  'token=s'     => \$token,
  'userfb=s'    => \$post_userfb,
  'comment=s'   => \$post_comment,
  'subscribe!'  => \$do_subscribe,
) or die "usage\n";

die "missing --token\n" if !$token;

my $JSON = JSON::PP->new->utf8(1)->canonical(1);

sub rand_bytes {
  my ($n) = @_;
  my $s = '';
  for (1..$n) { $s .= chr(int(rand(256))); }
  return $s;
}

sub ws_accept_value {
  my ($sec_key) = @_;
  my $GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  my $sha1_bin = sha1($sec_key . $GUID);
  return encode_base64($sha1_bin, '');
}

sub ws_mask {
  my ($payload, $mask) = @_;
  my @m = unpack("C4", $mask);
  my $out = $payload;
  for (my $i = 0; $i < length($out); $i++) {
    substr($out, $i, 1) = chr(ord(substr($out, $i, 1)) ^ $m[$i % 4]);
  }
  return $out;
}

sub ws_frame_text_client {
  my ($text) = @_;
  my $payload = $text;
  my $len = length($payload);
  my $b1 = 0x81; # FIN=1 opcode=1
  my $maskbit = 0x80;

  my $hdr = pack("C", $b1);
  if ($len < 126) {
    $hdr .= pack("C", $maskbit | $len);
  } elsif ($len <= 0xFFFF) {
    $hdr .= pack("C n", $maskbit | 126, $len);
  } else {
    my $hi = int($len / 4294967296);
    my $lo = $len % 4294967296;
    $hdr .= pack("C N N", $maskbit | 127, $hi, $lo);
  }

  my $mask = rand_bytes(4);
  my $masked = ws_mask($payload, $mask);
  return $hdr . $mask . $masked;
}

sub ws_parse_frames {
  my ($bufref) = @_;
  my @out;
  while (1) {
    last if length($$bufref) < 2;
    my ($b1, $b2) = unpack("C2", substr($$bufref, 0, 2));
    my $fin = ($b1 & 0x80) ? 1 : 0;
    my $opcode = ($b1 & 0x0F);
    my $masked = ($b2 & 0x80) ? 1 : 0;
    my $len = ($b2 & 0x7F);
    my $pos = 2;

    last if !$fin;

    if ($len == 126) {
      last if length($$bufref) < $pos + 2;
      $len = unpack("n", substr($$bufref, $pos, 2));
      $pos += 2;
    } elsif ($len == 127) {
      last if length($$bufref) < $pos + 8;
      my ($hi, $lo) = unpack("N N", substr($$bufref, $pos, 8));
      $pos += 8;
      last if $hi != 0;
      $len = $lo;
    }

    # server frames are not masked
    last if $masked;

    last if length($$bufref) < $pos + $len;
    my $payload = substr($$bufref, $pos, $len);
    $pos += $len;
    substr($$bufref, 0, $pos, '');

    push @out, [$opcode, $payload];
  }
  return @out;
}

my $sock = IO::Socket::INET->new(
  PeerAddr => $host,
  PeerPort => $port,
  Proto    => 'tcp',
) or die "connect failed\n";

binmode($sock, ":raw");

my $sec_key = encode_base64(rand_bytes(16), '');
my $path = "/facebook/users/online-chat?token=$token";

my $req =
  "GET $path HTTP/1.1\r\n" .
  "Host: $host:$port\r\n" .
  "Upgrade: websocket\r\n" .
  "Connection: Upgrade\r\n" .
  "Sec-WebSocket-Key: $sec_key\r\n" .
  "Sec-WebSocket-Version: 13\r\n" .
  "\r\n";

print $sock $req;

# read handshake response
my $resp = '';
while ($resp !~ /\r\n\r\n/s) {
  my $buf = '';
  my $n = sysread($sock, $buf, 4096);
  die "handshake failed\n" if !defined $n || $n == 0;
  $resp .= $buf;
  last if length($resp) > 65536;
}

my ($hdrs, $rest) = split /\r\n\r\n/s, $resp, 2;
my ($status_line) = split /\r\n/, $hdrs, 2;
if ($status_line !~ m{\AHTTP/1\.\d\s+101\b}) {
  # server error body is ONLY ERC_I_<n> (may be in $rest or later)
  my $body = $rest // '';
  if ($body eq '') {
    my $buf = '';
    sysread($sock, $buf, 64);
    $body .= $buf;
  }
  $body =~ s/\s+//g;
  print "$body\n";
  exit 1;
}

my $inbuf = $rest // '';

if ($do_subscribe) {
  my $sub = $JSON->encode({ op => "subscribe" });
  print $sock ws_frame_text_client($sub);
}

if ($post_userfb ne '' || $post_comment ne '') {
  my $post = $JSON->encode({ op => "post", UserFb => $post_userfb, Comment => $post_comment });
  print $sock ws_frame_text_client($post);
}

# read loop
while (1) {
  my $buf = '';
  my $n = sysread($sock, $buf, 4096);
  last if !defined $n || $n == 0;
  $inbuf .= $buf;

  my @frames = ws_parse_frames(\$inbuf);
  for my $fr (@frames) {
    my ($op, $payload) = @$fr;
    if ($op == 1) {
      print "$payload\n";
    } elsif ($op == 8) {
      exit 0;
    }
  }
}
