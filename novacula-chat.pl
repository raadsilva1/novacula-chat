#!/usr/bin/env perl
use strict;
use warnings;
use feature qw(state);

use IO::Socket::INET;
use IO::Select;
use Fcntl qw(:flock);
use POSIX qw(strftime);
use Digest::SHA qw(sha1 sha256 hmac_sha256);
use MIME::Base64 qw(encode_base64 decode_base64);
use JSON::PP ();
use Encode qw(decode encode);

select(STDERR); $| = 1;
select(STDOUT); $| = 1;

my $LISTEN_HOST        = '0.0.0.0';
my $LISTEN_PORT        = 39007;

my $BASE_DIR           = '/var/lib/novacula-chat';
my $CHAT_ENC_PATH      = "$BASE_DIR/chat.json.enc";
my $STATE_PATH         = "$BASE_DIR/state.json";
my $LOCK_PATH          = "$BASE_DIR/chat.lock";

my $PURGE_INTERVAL_S   = 50 * 3600;
my $CHAL_MAGIC         = "NCCHAL1";
my $CHAL_WINDOW_S      = 300;
my $TOKEN_EXP_S        = 21600;

my $MAX_MESSAGES       = 5000;
my $MAX_COMMENT_BYTES  = 2048;
my $MAX_FRAME_BYTES    = 8192;
my $MAX_MSG_BYTES      = 8192;
my $MAX_WORKERS        = 10;

my $PING_INTERVAL_S    = 30;
my $PONG_TIMEOUT_S     = 90;

# ALWAYS use Mac mini M1 UA (as requested)
my $IG_USER_AGENT      = 'Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15';

# Tiny IG cache (10 minutes)
my $IG_CACHE_TTL_S      = 600;
my $IG_CACHE_MAX        = 2048;
my %IG_CACHE;                  # lc(username) => { ok => 0/1, exp => epoch }
my $IG_CACHE_LAST_SWEEP = time();

# CORS (default: allow all)
my $CORS_ALL = 1;
my %CORS_ALLOW;                # exact origin => 1 (when restricting)

# NEW: if set via CLI, bypass Instagram curl validation completely
my $DO_NOT_CHECK_IG = 0;

my %ERC = (
  MALFORMED          => 1,
  AUTH_MISSING       => 2,
  AUTH_EXPIRED       => 3,
  CHAL_INVALID       => 4,
  CHAL_TS_WINDOW     => 5,
  INTS_INVALID       => 6,
  IG_FORMAT          => 7,
  IG_NOT_FOUND       => 8,
  COMMENT_INVALID    => 9,
  PERSIST_FAIL       => 10,
  SERVER_BUSY        => 11,
  WS_PROTOCOL        => 12,
);

my $JSON_ENC       = JSON::PP->new->utf8(1)->canonical(1);
my $JSON_DEC_BYTES = JSON::PP->new->utf8(1);
my $JSON_DEC_CHARS = JSON::PP->new->utf8(0);

my $AUTH_SECRET = $ENV{NOVACULA_AUTH_SECRET};
my $CHAT_KEY    = $ENV{NOVACULA_CHAT_KEY};

my @CHAT_CACHE;
my $LAST_PURGE_TS = 0;
my $FATAL_PERSISTENCE = 0;

my $NEXT_CONN_ID = 1;
my %CONN;
my %WORKER;
my $ACTIVE_WORKERS = 0;

my $LAST_WS_JSON_ERR = '';

my $BUILD_ID = do {
  my $mt = (stat(__FILE__))[9] || time();
  strftime("%Y%m%d-%H%M%S", gmtime($mt));
};

sub log_err {
  my ($msg) = @_;
  my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime(time));
  print STDERR "[$ts] $msg\n";
}
sub dbg {
  return unless $ENV{NOVACULA_DEBUG_WS};
  log_err("DEBUG: " . join("", @_));
}
sub dbg_ig {
  return unless $ENV{NOVACULA_DEBUG_IG};
  log_err("IG: " . join("", @_));
}

sub parse_cli_args {
  my @a = @ARGV;
  while (@a) {
    my $x = shift @a;
    if ($x eq '--cors') {
      # default is allow-all even if flag is present without value
      $CORS_ALL = 1;
      %CORS_ALLOW = ();
      if (@a && $a[0] !~ /^\-\-/) {
        my $v = shift @a;
        $v //= '';
        $v =~ s/^\s+|\s+$//g;
        if ($v ne '' && $v ne '*') {
          my %h;
          for my $o (split /,/, $v) {
            $o =~ s/^\s+|\s+$//g;
            next if $o eq '';
            $h{$o} = 1;
          }
          if (%h) { $CORS_ALL = 0; %CORS_ALLOW = %h; }
        }
      }
    } elsif ($x eq '--do-not-check-ig') {
      $DO_NOT_CHECK_IG = 1;
    } else {
      # ignore unknown flags (do not break existing deployments)
      log_err("Ignoring unknown CLI arg: $x");
    }
  }
}
parse_cli_args();

sub cors_headers_for_req {
  my ($req) = @_;
  my $origin = $req && $req->{headers} ? ($req->{headers}{origin} // '') : '';
  my $h = '';

  if ($CORS_ALL) {
    $h .= "Access-Control-Allow-Origin: *\r\n";
    $h .= "Access-Control-Allow-Methods: GET,PATCH,OPTIONS\r\n";
    $h .= "Access-Control-Allow-Headers: Content-Type\r\n";
    $h .= "Access-Control-Max-Age: 600\r\n";
    return $h;
  }

  return '' if $origin eq '';
  return '' if !$CORS_ALLOW{$origin};

  $h .= "Access-Control-Allow-Origin: $origin\r\n";
  $h .= "Vary: Origin\r\n";
  $h .= "Access-Control-Allow-Methods: GET,PATCH,OPTIONS\r\n";
  $h .= "Access-Control-Allow-Headers: Content-Type\r\n";
  $h .= "Access-Control-Max-Age: 600\r\n";
  return $h;
}

sub _dump_bytes_preview {
  my ($bytes) = @_;
  my $hex = unpack("H*", substr($bytes // '', 0, 300));
  my $asc = substr($bytes // '', 0, 300);
  $asc =~ s/[^[:print:]\r\n\t]/./g;
  return ($hex, $asc);
}

sub log_ws_malformed {
  my (%p) = @_;
  my ($hex, $asc) = _dump_bytes_preview($p{payload});
  my $je = $LAST_WS_JSON_ERR // '';
  $je =~ s/[\r\n]/ /g;
  $je = substr($je, 0, 500);
  log_err("WS MALFORMED: fin=$p{fin} op=$p{opcode} rsv1=$p{rsv1} masked=$p{masked} len=$p{len} jsonerr=$je hex=$hex asc=$asc");
}

sub b64url_encode {
  my ($bytes) = @_;
  my $b64 = encode_base64($bytes, '');
  $b64 =~ tr!+/!-_!;
  $b64 =~ s/=+\z//;
  return $b64;
}
sub b64url_decode {
  my ($s) = @_;
  $s =~ tr!-_!+/!;
  my $pad = (4 - (length($s) % 4)) % 4;
  $s .= '=' x $pad;
  my $out = eval { decode_base64($s) };
  return (defined $out) ? $out : undef;
}
sub secure_eq {
  my ($a, $b) = @_;
  return 0 if !defined($a) || !defined($b);
  return 0 if length($a) != length($b);
  my $r = 0;
  for (my $i = 0; $i < length($a); $i++) {
    $r |= (ord(substr($a, $i, 1)) ^ ord(substr($b, $i, 1)));
  }
  return $r == 0;
}

sub url_decode {
  my ($s) = @_;
  $s =~ s/\+/ /g;
  $s =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
  return $s;
}
sub parse_query {
  my ($qs) = @_;
  my %q;
  return \%q if !defined $qs || $qs eq '';
  for my $pair (split /&/, $qs) {
    my ($k, $v) = split /=/, $pair, 2;
    $k = url_decode($k // '');
    $v = url_decode($v // '');
    $q{$k} = $v;
  }
  return \%q;
}

sub http_resp {
  my ($status, $ctype, $body, $extra_headers) = @_;
  $extra_headers ||= '';
  my $len = defined($body) ? length($body) : 0;
  return
    "HTTP/1.1 $status\r\n" .
    "Content-Type: $ctype\r\n" .
    "Content-Length: $len\r\n" .
    "Connection: close\r\n" .
    $extra_headers .
    "\r\n" .
    ($body // '');
}
sub http_err {
  my ($status, $erc_n, $req) = @_;
  return http_resp($status, "text/plain", "ERC_I_$erc_n", cors_headers_for_req($req));
}
sub http_queue_and_close {
  my ($c, $resp) = @_;
  $c->{outbuf} .= $resp;
  $c->{close_after_write} = 1;
  $c->{state} = 'http_close';
}
sub http_preflight_ok {
  my ($req) = @_;
  return http_resp("204 No Content", "text/plain", "", cors_headers_for_req($req));
}

# WebSocket
sub ws_accept_value {
  my ($sec_key) = @_;
  my $GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  my $sha1_bin = sha1($sec_key . $GUID);
  return encode_base64($sha1_bin, '');
}
sub ws_frame_text {
  my ($text) = @_;
  my $payload = $text;
  my $len = length($payload);
  my $hdr = pack("C", 0x81);
  if ($len < 126) {
    $hdr .= pack("C", $len);
  } elsif ($len <= 0xFFFF) {
    $hdr .= pack("C n", 126, $len);
  } else {
    my $hi = int($len / 4294967296);
    my $lo = $len % 4294967296;
    $hdr .= pack("C N N", 127, $hi, $lo);
  }
  return $hdr . $payload;
}
sub ws_frame_pong {
  my ($payload) = @_;
  my $len = length($payload);
  my $hdr = pack("C", 0x8A);
  if ($len < 126) {
    $hdr .= pack("C", $len);
  } elsif ($len <= 0xFFFF) {
    $hdr .= pack("C n", 126, $len);
  } else {
    my $hi = int($len / 4294967296);
    my $lo = $len % 4294967296;
    $hdr .= pack("C N N", 127, $hi, $lo);
  }
  return $hdr . $payload;
}
sub ws_frame_ping {
  my ($payload) = @_;
  $payload //= '';
  my $len = length($payload);
  my $hdr = pack("C", 0x89);
  if ($len < 126) {
    $hdr .= pack("C", $len);
  } elsif ($len <= 0xFFFF) {
    $hdr .= pack("C n", 126, $len);
  } else {
    my $hi = int($len / 4294967296);
    my $lo = $len % 4294967296;
    $hdr .= pack("C N N", 127, $hi, $lo);
  }
  return $hdr . $payload;
}
sub ws_frame_close { return pack("C C", 0x88, 0x00); }

sub conn_queue_bytes { my ($c, $bytes) = @_; $c->{outbuf} .= $bytes; }
sub conn_send_ws_json {
  my ($c, $obj) = @_;
  my $txt = eval { $JSON_ENC->encode($obj) };
  if (!defined $txt) { conn_send_ws_err($c, $ERC{MALFORMED}); return; }
  conn_queue_bytes($c, ws_frame_text($txt));
}
sub conn_send_ws_err {
  my ($c, $erc_n) = @_;
  conn_send_ws_json($c, { op => "err", code => "ERC_I_$erc_n" });
}

# Tiny IG cache helpers
sub ig_cache_sweep {
  my ($force) = @_;
  my $now = time();
  return if !$force && ($now - $IG_CACHE_LAST_SWEEP) < 30;
  $IG_CACHE_LAST_SWEEP = $now;
  for my $k (keys %IG_CACHE) {
    delete $IG_CACHE{$k} if (($IG_CACHE{$k}{exp} // 0) <= $now);
  }
}
sub ig_cache_get {
  my ($userfb) = @_;
  ig_cache_sweep(0);
  my $k = lc($userfb // '');
  return undef if $k eq '';
  my $e = $IG_CACHE{$k} or return undef;
  if (($e->{exp} // 0) <= time()) { delete $IG_CACHE{$k}; return undef; }
  return $e->{ok} ? 1 : 0;
}
sub ig_cache_set {
  my ($userfb, $ok) = @_;
  my $k = lc($userfb // '');
  return if $k eq '';
  $IG_CACHE{$k} = { ok => $ok ? 1 : 0, exp => time() + $IG_CACHE_TTL_S };
  if (scalar(keys %IG_CACHE) > $IG_CACHE_MAX) {
    ig_cache_sweep(1);
    if (scalar(keys %IG_CACHE) > $IG_CACHE_MAX) { %IG_CACHE = (); }
  }
}

# filesystem + openssl
sub ensure_base_dir { if (!-d $BASE_DIR) { mkdir $BASE_DIR or die "mkdir base dir failed"; } }
sub lock_fh {
  ensure_base_dir();
  open(my $lfh, ">>", $LOCK_PATH) or return undef;
  flock($lfh, LOCK_EX) or return undef;
  return $lfh;
}
sub atomic_write_file {
  my ($path, $bytes) = @_;
  my $tmp = "$path.tmp";
  open(my $fh, ">", $tmp) or return 0;
  binmode($fh, ":raw");
  my $ok = print $fh $bytes;
  $ok = $ok && close($fh);
  return 0 if !$ok;
  return rename($tmp, $path) ? 1 : 0;
}
sub run_cmd_capture {
  my ($argv, $input_bytes) = @_;
  require IPC::Open3;
  require Symbol;
  my $err = Symbol::gensym();
  my ($wtr, $rdr);
  my $pid = eval { IPC::Open3::open3($wtr, $rdr, $err, @$argv) };
  if (!$pid) { return (0, '', 'spawn_fail'); }

  binmode($wtr, ":raw");
  binmode($rdr, ":raw");
  binmode($err, ":raw");

  if (defined $input_bytes && length($input_bytes)) {
    my $off = 0;
    while ($off < length($input_bytes)) {
      my $n = syswrite($wtr, $input_bytes, length($input_bytes) - $off, $off);
      last if !defined $n;
      $off += $n;
    }
  }
  close($wtr);

  my $sel = IO::Select->new();
  $sel->add($rdr);
  $sel->add($err);
  my ($out, $e) = ('', '');
  while ($sel->count) {
    for my $fh ($sel->can_read(2)) {
      my $buf = '';
      my $n = sysread($fh, $buf, 8192);
      if (!defined $n || $n == 0) { $sel->remove($fh); next; }
      if ($fh == $rdr) { $out .= $buf; } else { $e .= $buf; }
    }
  }

  waitpid($pid, 0);
  my $rc = ($? >> 8);
  return ($rc == 0 ? 1 : 0, $out, $e);
}
sub encrypt_bytes {
  my ($plaintext) = @_;
  return undef if !defined $CHAT_KEY || $CHAT_KEY eq '';
  my $argv = [
    'openssl', 'enc', '-aes-256-cbc',
    '-pbkdf2', '-iter', '200000', '-salt',
    '-pass', 'env:NOVACULA_CHAT_KEY'
  ];
  my ($ok, $out, $e) = run_cmd_capture($argv, $plaintext);
  if (!$ok) { log_err("openssl encrypt failed: $e"); return undef; }
  return $out;
}
sub decrypt_bytes_from_file {
  my ($path) = @_;
  return undef if !defined $CHAT_KEY || $CHAT_KEY eq '';
  return '[]' if !-e $path;

  open(my $fh, "<", $path) or return undef;
  binmode($fh, ":raw");
  local $/;
  my $cipher = <$fh>;
  close($fh);

  my $argv = [
    'openssl', 'enc', '-d', '-aes-256-cbc',
    '-pbkdf2', '-iter', '200000', '-salt',
    '-pass', 'env:NOVACULA_CHAT_KEY'
  ];
  my ($ok, $out, $e) = run_cmd_capture($argv, $cipher);
  if (!$ok) { log_err("openssl decrypt failed: $e"); return undef; }
  return $out;
}

sub load_state_locked {
  $LAST_PURGE_TS = 0;
  if (!-e $STATE_PATH) {
    $LAST_PURGE_TS = time();
    my $bytes = $JSON_ENC->encode({ last_purge_ts => $LAST_PURGE_TS });
    atomic_write_file($STATE_PATH, $bytes) or return 0;
    return 1;
  }
  open(my $fh, "<", $STATE_PATH) or return 0;
  binmode($fh, ":raw");
  local $/;
  my $b = <$fh>;
  close($fh);

  my $st = eval { $JSON_DEC_BYTES->decode($b) };
  if (!$st || ref($st) ne 'HASH' || !defined $st->{last_purge_ts} || $st->{last_purge_ts} !~ /^\d+$/) {
    $LAST_PURGE_TS = time();
    my $bytes = $JSON_ENC->encode({ last_purge_ts => $LAST_PURGE_TS });
    atomic_write_file($STATE_PATH, $bytes) or return 0;
    return 1;
  }
  $LAST_PURGE_TS = int($st->{last_purge_ts});
  return 1;
}
sub save_state_locked {
  my $bytes = $JSON_ENC->encode({ last_purge_ts => $LAST_PURGE_TS });
  return atomic_write_file($STATE_PATH, $bytes);
}
sub load_chat_locked {
  my $plain = decrypt_bytes_from_file($CHAT_ENC_PATH);
  return 0 if !defined $plain;
  my $arr = eval { $JSON_DEC_BYTES->decode($plain) };
  return 0 if !$arr || ref($arr) ne 'ARRAY';
  @CHAT_CACHE = @$arr;
  return 1;
}
sub persist_chat_locked {
  my $plain = eval { $JSON_ENC->encode(\@CHAT_CACHE) };
  return 0 if !defined $plain;
  my $enc = encrypt_bytes($plain);
  return 0 if !defined $enc;
  return atomic_write_file($CHAT_ENC_PATH, $enc);
}
sub enforce_max_messages {
  if (@CHAT_CACHE > $MAX_MESSAGES) {
    my $drop = @CHAT_CACHE - $MAX_MESSAGES;
    splice(@CHAT_CACHE, 0, $drop);
  }
}
sub purge_if_due_locked {
  my $now = time();
  if (!$LAST_PURGE_TS) {
    $LAST_PURGE_TS = $now;
    save_state_locked() or return 0;
    return 1;
  }
  if (($now - $LAST_PURGE_TS) >= $PURGE_INTERVAL_S) {
    @CHAT_CACHE = ();
    enforce_max_messages();
    $LAST_PURGE_TS = $now;
    save_state_locked() or return 0;
    persist_chat_locked() or return 0;
  }
  return 1;
}

# token
sub token_generate {
  my ($ts) = @_;
  return undef if !defined($AUTH_SECRET) || $AUTH_SECRET eq '';
  my $obj = { v => 1, ts => $ts, exp => ($ts + $TOKEN_EXP_S) };
  my $body_json = $JSON_ENC->encode($obj);
  my $token_body = b64url_encode($body_json);
  my $sig_bin = hmac_sha256($token_body, $AUTH_SECRET);
  my $sig = b64url_encode($sig_bin);
  return $token_body . "." . $sig;
}
sub token_verify {
  my ($tok) = @_;
  return (0, $ERC{AUTH_MISSING}) if !defined($tok) || $tok eq '';
  return (0, $ERC{AUTH_MISSING}) if $tok !~ /\A([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)\z/;
  my ($tb, $sig) = ($1, $2);
  return (0, $ERC{AUTH_MISSING}) if !defined($AUTH_SECRET) || $AUTH_SECRET eq '';

  my $expect = b64url_encode(hmac_sha256($tb, $AUTH_SECRET));
  return (0, $ERC{AUTH_MISSING}) if !secure_eq($sig, $expect);

  my $json = b64url_decode($tb);
  return (0, $ERC{AUTH_MISSING}) if !defined $json;

  my $obj = eval { $JSON_DEC_BYTES->decode($json) };
  return (0, $ERC{AUTH_MISSING}) if !$obj || ref($obj) ne 'HASH';
  return (0, $ERC{AUTH_MISSING}) if !defined $obj->{exp} || $obj->{exp} !~ /^\d+$/;

  my $now = time();
  return (0, $ERC{AUTH_EXPIRED}) if int($obj->{exp}) < $now;

  return (1, $obj);
}

# instagram local format
sub ig_format_ok {
  my ($u) = @_;
  return 0 if !defined($u);
  return 0 if length($u) < 1 || length($u) > 30;
  return 0 if $u !~ /\A[A-Za-z0-9._]+\z/;
  return 0 if $u =~ /\.\./;
  return 0 if $u =~ /\A\./ || $u =~ /\.\z/;
  return 1;
}

sub accept_post_after_validation {
  my ($conn, $userfb, $comment_utf8) = @_;

  my $comment_chars = eval { decode('UTF-8', $comment_utf8, Encode::FB_CROAK) };
  if ($@ || !defined $comment_chars) {
    log_err("COMMENT_INVALID: decode_utf8_failed in accept_post_after_validation");
    conn_send_ws_err($conn, $ERC{COMMENT_INVALID});
    return;
  }

  my $now = time();
  my $lfh = lock_fh();
  if (!$lfh) { conn_send_ws_err($conn, $ERC{PERSIST_FAIL}); return; }

  if (!load_state_locked())   { close($lfh); conn_send_ws_err($conn, $ERC{PERSIST_FAIL}); return; }
  if (!purge_if_due_locked()) { close($lfh); conn_send_ws_err($conn, $ERC{PERSIST_FAIL}); return; }

  my $entry = {
    UnixTimestamp => $now,
    UserFb        => $userfb,
    DateHour      => strftime("%d-%m-%Y %H:%M:%S", localtime($now)),
    Comment       => $comment_chars,
  };

  push @CHAT_CACHE, $entry;
  enforce_max_messages();

  if (!persist_chat_locked()) { close($lfh); conn_send_ws_err($conn, $ERC{PERSIST_FAIL}); return; }
  close($lfh);

  for my $k (keys %CONN) {
    my $cc = $CONN{$k};
    next if $cc->{state} ne 'ws';
    next if !$cc->{subscribed};
    conn_send_ws_json($cc, { op => "msg", data => $entry });
  }
}

# workers
sub start_ig_worker {
  my ($c, $userfb, $comment_utf8) = @_;
  if ($ACTIVE_WORKERS >= $MAX_WORKERS) { conn_send_ws_err($c, $ERC{SERVER_BUSY}); return; }

  pipe(my $r, my $w) or do { conn_send_ws_err($c, $ERC{IG_NOT_FOUND}); return; };

  my $pid = fork();
  if (!defined $pid) { close($r); close($w); conn_send_ws_err($c, $ERC{IG_NOT_FOUND}); return; }

  if ($pid == 0) {
    close($r);
    binmode($w, ":raw");
    my $url = "https://www.instagram.com/$userfb";

    # No Range, force http1.1
    my @cmd = (
      'curl',
      '--http1.1',
      '--connect-timeout', '2',
      '--max-time', '6',
      '-L',
      '-sS',
      '-A', $IG_USER_AGENT,
      '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      '-H', 'Accept-Language: en-US,en;q=0.9',
      $url,
      '-w', "\nNC_HTTP_CODE:%{http_code}\n"
    );

    my $out = '';
    my $ok = 0;

    {
      local $SIG{ALRM} = sub { die "timeout\n" };
      alarm 8;
      if (open(my $ch, "-|", @cmd)) {
        local $/;
        $out = <$ch> // '';
        close($ch);
        $ok = 1;
      }
      alarm 0;
    }

    if (!$ok || $out eq '') { dbg_ig("check userfb=$userfb result=NO reason=curl_empty"); print $w "NO\n"; close($w); exit 0; }

    my $code = '';
    if ($out =~ s/\nNC_HTTP_CODE:(\d{3})\n\z//) { $code = $1; }
    else { dbg_ig("check userfb=$userfb result=NO reason=no_http_code_marker"); print $w "NO\n"; close($w); exit 0; }

    if ($code eq '404') { dbg_ig("check userfb=$userfb http=$code result=NO"); print $w "NO\n"; close($w); exit 0; }
    if ($code eq '403' || $code eq '429') { dbg_ig("check userfb=$userfb http=$code result=NO (blocked/rate-limited)"); print $w "NO\n"; close($w); exit 0; }

    if ($code !~ /\A(200|206|301|302|303|307|308)\z/) { dbg_ig("check userfb=$userfb http=$code result=NO (unhandled_code)"); print $w "NO\n"; close($w); exit 0; }

    my $lc = lc($out);

    if ($lc =~ /polarisrouteconfig"\s*:\s*\{\s*"pageid"\s*:\s*"httperrorpage"/) {
      dbg_ig("check userfb=$userfb http=$code result=NO (httpErrorPage)");
      print $w "NO\n"; close($w); exit 0;
    }

    my $u = $userfb;
    $u =~ s/([\\"])/\\$1/g;
    if ($lc =~ /"pageid"\s*:\s*"httperrorpage".{0,2000}"url"\s*:\s*"\\\/\Q$u\E"/s) {
      dbg_ig("check userfb=$userfb http=$code result=NO (httpErrorPage_url_match)");
      print $w "NO\n"; close($w); exit 0;
    }

    dbg_ig("check userfb=$userfb http=$code result=OK");
    print $w "OK\n"; close($w); exit 0;
  }

  close($w);
  $r->blocking(0);

  my $fil = fileno($r);
  $WORKER{$fil} = {
    fh           => $r,
    pid          => $pid,
    conn_id      => $c->{id},
    userfb       => $userfb,
    comment_utf8 => $comment_utf8,
    start        => time(),
    buf          => '',
  };
  $ACTIVE_WORKERS++;
  $c->{pending_post} = 1;
  $c->{pending_worker_pid} = $pid;
}

sub finish_worker {
  my ($fil, $result_ok) = @_;
  my $w = $WORKER{$fil};
  return if !$w;

  my $conn_id = $w->{conn_id};
  my ($conn_fileno) = grep { $CONN{$_}{id} == $conn_id } keys %CONN;
  my $conn = defined($conn_fileno) ? $CONN{$conn_fileno} : undef;

  if ($conn) { $conn->{pending_post} = 0; $conn->{pending_worker_pid} = undef; }

  my $fh = $w->{fh};
  delete $WORKER{$fil};
  $ACTIVE_WORKERS-- if $ACTIVE_WORKERS > 0;
  close($fh);

  ig_cache_set($w->{userfb}, $result_ok ? 1 : 0);

  return if !$conn;

  if (!$result_ok) { conn_send_ws_err($conn, $ERC{IG_NOT_FOUND}); return; }

  accept_post_after_validation($conn, $w->{userfb}, $w->{comment_utf8});
}

sub kill_worker_for_conn {
  my ($conn) = @_;
  return if !$conn->{pending_worker_pid};
  kill 9, $conn->{pending_worker_pid};
  $conn->{pending_worker_pid} = undef;
  $conn->{pending_post} = 0;
}

# challenge math (BigInt)
sub _mbi { require Math::BigInt; return Math::BigInt->new($_[0]); }
sub u64_mask { state $MASK = do { require Math::BigInt; (Math::BigInt->new(1) << 64) - 1; }; return $MASK->copy(); }
sub u64_mod  { my ($x)=@_; state $MOD = do { require Math::BigInt; (Math::BigInt->new(1) << 64); }; my $y=_mbi("$x"); $y->bmod($MOD); return $y; }
sub u64_and_mask { my ($x)=@_; my $m=u64_mask(); $x->band($m); return $x; }
sub u64_rotl {
  my ($s, $r) = @_;
  my $m = u64_mask();
  my $left  = $s->copy(); $left->blsft($r); $left->band($m);
  my $right = $s->copy(); $right->brsft(64 - $r); $right->band($m);
  $left->bior($right); $left->band($m);
  return $left;
}
sub u64_le_pack {
  my ($x_u64_bigint) = @_;
  my $MASK32 = 4294967295;
  my $lo = ($x_u64_bigint->copy()->band($MASK32))->numify();
  my $hi = ($x_u64_bigint->copy()->brsft(32)->band($MASK32))->numify();
  return pack("V V", $lo, $hi);
}
sub parse_100_ints {
  my ($values_str) = @_;
  return (0, undef) if !defined $values_str;
  my @parts = split /,/, $values_str;
  return (0, undef) if @parts != 100;

  require Math::BigInt;
  my $MIN = Math::BigInt->new("-9223372036854775808");
  my $MAX = Math::BigInt->new("9223372036854775807");

  my @V;
  for my $p (@parts) {
    return (0, undef) if $p !~ /\A-?\d+\z/;
    my $bi = Math::BigInt->new($p);
    return (0, undef) if $bi->bcmp($MIN) < 0 || $bi->bcmp($MAX) > 0;
    push @V, $bi;
  }
  return (1, \@V);
}
sub compute_challenge_b64 {
  my ($V) = @_;
  require Math::BigInt;

  my $S  = Math::BigInt->new("0x9E3779B97F4A7C15");
  my $C1 = Math::BigInt->new("0xBF58476D1CE4E5B9");
  my $C2 = Math::BigInt->new("0x94D049BB133111EB");

  for (my $i = 0; $i < 100; $i++) {
    my $x = u64_mod($V->[$i]);
    my $t = $x->copy(); $t->badd($C1); u64_and_mask($t);
    $S->bxor($t); u64_and_mask($S);
    $S->bmul($C2); u64_and_mask($S);
    $S = u64_rotl($S, ($i % 63) + 1);
  }

  my $blob = u64_le_pack($S);
  for (my $i = 0; $i < 100; $i++) {
    my $x = u64_mod($V->[$i]);
    $blob .= u64_le_pack($x);
  }

  my $digest = sha256($blob);
  my $ts = time();
  my $payload = $CHAL_MAGIC . u64_le_pack(u64_mod($ts)) . $digest;
  return encode_base64($payload, '');
}
sub parse_challenge_payload {
  my ($b64) = @_;
  my $raw = eval { decode_base64($b64) };
  return (0, $ERC{CHAL_INVALID}) if !defined $raw;
  return (0, $ERC{CHAL_INVALID}) if length($raw) != (7 + 8 + 32);
  return (0, $ERC{CHAL_INVALID}) if substr($raw, 0, 7) ne $CHAL_MAGIC;

  my ($lo, $hi) = unpack("V V", substr($raw, 7, 8));
  my $ts = $hi * 4294967296 + $lo;

  return (0, $ERC{CHAL_TS_WINDOW}) if abs(time() - $ts) > $CHAL_WINDOW_S;
  return (1, $ts);
}

sub try_parse_http_req {
  my ($c) = @_;
  my $buf = $c->{inbuf};
  my $idx = index($buf, "\r\n\r\n");
  return undef if $idx < 0;

  my $head = substr($buf, 0, $idx);
  my $rest = substr($buf, $idx + 4);

  my @lines = split /\r\n/, $head;
  return { err => $ERC{MALFORMED} } if !@lines;

  my $reqline = shift @lines;
  my ($method, $target, $ver) = split / /, $reqline, 3;
  return { err => $ERC{MALFORMED} } if !defined($method) || !defined($target) || !defined($ver);
  return { err => $ERC{MALFORMED} } if $ver !~ m{\AHTTP/1\.[01]\z};

  my %h;
  for my $ln (@lines) {
    next if $ln eq '';
    return { err => $ERC{MALFORMED} } if $ln !~ /\A([^:]+):\s*(.*)\z/;
    my $k = lc($1);
    my $v = $2; $v =~ s/\s+\z//;
    $h{$k} = $v;
  }

  my $cl = 0;
  if (defined $h{'content-length'}) {
    return { err => $ERC{MALFORMED} } if $h{'content-length'} !~ /\A\d+\z/;
    $cl = int($h{'content-length'});
    return { err => $ERC{MALFORMED} } if $cl < 0 || $cl > 1024*1024;
  }

  return undef if length($rest) < $cl;

  my $body = ($cl > 0) ? substr($rest, 0, $cl) : '';
  my $remain = substr($rest, $cl);
  $c->{inbuf} = $remain;

  my ($path, $qs) = split /\?/, $target, 2;
  my $q = parse_query($qs // '');

  return {
    method  => uc($method),
    target  => $target,
    path    => $path,
    query   => $q,
    ver     => $ver,
    headers => \%h,
    body    => $body,
  };
}

sub handle_http_run_challenge_get {
  my ($req) = @_;
  my ($ok, $V) = parse_100_ints($req->{query}{values});
  return http_err("400 Bad Request", $ERC{INTS_INVALID}, $req) if !$ok;
  return http_resp("200 OK", "text/plain", compute_challenge_b64($V), cors_headers_for_req($req));
}
sub handle_http_run_challenge_patch {
  my ($req) = @_;
  my $ct = lc($req->{headers}{'content-type'} // '');
  return http_err("400 Bad Request", $ERC{MALFORMED}, $req) if $ct !~ /\Atext\/plain\b/;

  my $b64 = $req->{body} // '';
  $b64 =~ s/\s+//g;

  my ($ok, $ts_or_err) = parse_challenge_payload($b64);
  return http_err("400 Bad Request", $ts_or_err, $req) if !$ok;

  my $token = token_generate($ts_or_err);
  return http_err("500 Internal Server Error", $ERC{AUTH_MISSING}, $req) if !defined $token;

  return http_resp("200 OK", "text/plain", $token, cors_headers_for_req($req));
}

sub handle_ws_upgrade {
  my ($c, $req) = @_;

  my ($tv_ok, $tv_obj_or_err) = token_verify($req->{query}{token});
  if (!$tv_ok) { return (0, http_err("401 Unauthorized", $tv_obj_or_err, $req)); }

  my $h = $req->{headers};
  my $up = lc($h->{upgrade} // '');
  my $conn = lc($h->{connection} // '');
  my $sec_key = $h->{'sec-websocket-key'};
  my $ver = $h->{'sec-websocket-version'};

  return (0, http_err("400 Bad Request", $ERC{MALFORMED}, $req)) if $req->{method} ne 'GET';
  return (0, http_err("400 Bad Request", $ERC{MALFORMED}, $req)) if $up ne 'websocket';
  return (0, http_err("400 Bad Request", $ERC{MALFORMED}, $req)) if $conn !~ /\bupgrade\b/;
  return (0, http_err("400 Bad Request", $ERC{MALFORMED}, $req)) if !defined($sec_key) || $sec_key eq '';
  return (0, http_err("400 Bad Request", $ERC{MALFORMED}, $req)) if !defined($ver) || $ver ne '13';

  my $accept = ws_accept_value($sec_key);
  my $cors = cors_headers_for_req($req);

  my $resp =
    "HTTP/1.1 101 Switching Protocols\r\n" .
    "Upgrade: websocket\r\n" .
    "Connection: Upgrade\r\n" .
    "Sec-WebSocket-Accept: $accept\r\n" .
    $cors .
    "\r\n";

  $c->{state} = 'ws';
  $c->{subscribed} = 0;
  $c->{last_activity} = time();
  $c->{last_pong} = time();
  $c->{last_ping_sent} = 0;
  $c->{pending_post} = 0;
  $c->{pending_worker_pid} = undef;

  $c->{frag_active} = 0;
  $c->{frag_opcode} = 0;
  $c->{frag_data} = '';

  return (1, $resp);
}

sub ws_try_parse_client_obj {
  my ($bytes) = @_;
  $LAST_WS_JSON_ERR = '';

  my $b = $bytes // '';
  $b =~ s/\x00+\z//;
  $b =~ s/^\xEF\xBB\xBF//;
  $b =~ s/\A[ \t\r\n]+//;
  $b =~ s/[ \t\r\n]+\z//;
  if ($b eq '') { $LAST_WS_JSON_ERR = "empty_after_trim"; return undef; }

  my $chars = eval { decode('UTF-8', $b, Encode::FB_CROAK) };
  if ($@ || !defined $chars) {
    my ($hx,$as) = _dump_bytes_preview($b);
    $LAST_WS_JSON_ERR = "utf8_invalid blen=" . length($b) . " bhex=$hx basc=$as";
    return undef;
  }

  my $obj = eval { $JSON_DEC_CHARS->decode($chars) };
  if ($@) {
    my $e = $@; $e =~ s/[\r\n]/ /g;
    my ($hx,$as) = _dump_bytes_preview($b);
    $LAST_WS_JSON_ERR = "json_decode:$e blen=" . length($b) . " bhex=$hx basc=$as";
    return undef;
  }
  if (!$obj || ref($obj) ne 'HASH') { $LAST_WS_JSON_ERR = "json_not_object"; return undef; }
  if (!defined($obj->{op}) || $obj->{op} eq '') { $LAST_WS_JSON_ERR = "missing_op"; return undef; }
  return $obj;
}

sub ws_handle_message_obj {
  my ($c, $obj) = @_;
  my $op = $obj->{op} // '';
  $op = "$op"; $op =~ s/\A\s+//; $op =~ s/\s+\z//;

  if ($op eq 'subscribe') {
    if ($FATAL_PERSISTENCE) { conn_send_ws_err($c, $ERC{PERSIST_FAIL}); return; }
    $c->{subscribed} = 1;
    conn_send_ws_json($c, { op => "history", data => \@CHAT_CACHE });
    return;
  }

  if ($op eq 'post') {
    if (!$c->{subscribed}) { conn_send_ws_err($c, $ERC{MALFORMED}); return; }
    if ($FATAL_PERSISTENCE) { conn_send_ws_err($c, $ERC{PERSIST_FAIL}); return; }
    if ($c->{pending_post}) { conn_send_ws_err($c, $ERC{SERVER_BUSY}); return; }

    my $userfb  = $obj->{UserFb};
    my $comment = $obj->{Comment};

    if (!ig_format_ok($userfb)) { conn_send_ws_err($c, $ERC{IG_FORMAT}); return; }
    if (!defined $comment) { log_err("COMMENT_INVALID: missing Comment key"); conn_send_ws_err($c, $ERC{COMMENT_INVALID}); return; }

    $comment = "$comment";

    my $comment_utf8 = eval { encode('UTF-8', $comment, Encode::FB_CROAK) };
    if ($@ || !defined $comment_utf8) { log_err("COMMENT_INVALID: utf8_encode_fail"); conn_send_ws_err($c, $ERC{COMMENT_INVALID}); return; }

    my $comment_bytes = length($comment_utf8);
    if ($comment_bytes < 1 || $comment_bytes > $MAX_COMMENT_BYTES) {
      my ($hx,$as) = _dump_bytes_preview($comment_utf8);
      log_err("COMMENT_INVALID: bytes=$comment_bytes max=$MAX_COMMENT_BYTES hex=$hx asc=$as");
      conn_send_ws_err($c, $ERC{COMMENT_INVALID});
      return;
    }

    my $tmp = $comment_utf8;
    $tmp =~ s/[ \t\r\n\f\v]+//g;
    if (length($tmp) == 0) {
      my ($hx,$as) = _dump_bytes_preview($comment_utf8);
      log_err("COMMENT_INVALID: whitespace_only bytes=$comment_bytes hex=$hx asc=$as");
      conn_send_ws_err($c, $ERC{COMMENT_INVALID});
      return;
    }

    # NEW: bypass IG curl validation when CLI flag is set
    if ($DO_NOT_CHECK_IG) {
      dbg("IG bypass enabled: accepting post without IG check userfb=$userfb bytes=$comment_bytes");
      accept_post_after_validation($c, $userfb, $comment_utf8);
      return;
    }

    # IG cache short-circuit
    my $cached = ig_cache_get($userfb);
    if (defined $cached) {
      if ($cached) {
        dbg("IG cache hit OK: userfb=$userfb");
        accept_post_after_validation($c, $userfb, $comment_utf8);
      } else {
        dbg("IG cache hit NO: userfb=$userfb");
        conn_send_ws_err($c, $ERC{IG_NOT_FOUND});
      }
      return;
    }

    dbg("post accepted for validation: userfb=$userfb bytes=$comment_bytes");
    start_ig_worker($c, $userfb, $comment_utf8);
    return;
  }

  conn_send_ws_err($c, $ERC{MALFORMED});
}

sub ws_unmask {
  my ($payload, $mask) = @_;
  my @m = unpack("C4", $mask);
  my @p = unpack("C*", $payload);
  for (my $i = 0; $i < @p; $i++) { $p[$i] ^= $m[$i & 3]; }
  return pack("C*", @p);
}

sub conn_close {
  my ($sel, $c, $send_ws_close) = @_;
  my $fh = $c->{sock};
  my $fil = fileno($fh);

  if ($c->{state} eq 'ws' && $send_ws_close) {
    eval { syswrite($fh, ws_frame_close()) };
  }

  kill_worker_for_conn($c);
  for my $wf (keys %WORKER) {
    if ($WORKER{$wf}{conn_id} == $c->{id}) { kill 9, $WORKER{$wf}{pid}; }
  }

  $sel->remove($fh);
  delete $CONN{$fil};
  eval { close($fh) };
}

sub ws_process_frames {
  my ($sel, $c) = @_;
  my $bufref = \$c->{inbuf};

  while (1) {
    return if length($$bufref) < 2;
    my ($b1, $b2) = unpack("C2", substr($$bufref, 0, 2));

    my $fin       = ($b1 & 0x80) ? 1 : 0;
    my $rsv1      = ($b1 & 0x40) ? 1 : 0;
    my $rsv_other = ($b1 & 0x30) ? 1 : 0;
    my $opcode    = ($b1 & 0x0F);

    my $masked = ($b2 & 0x80) ? 1 : 0;
    my $len    = ($b2 & 0x7F);
    my $pos    = 2;

    if ($rsv_other || $rsv1) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }

    if ($len == 126) {
      return if length($$bufref) < $pos + 2;
      $len = unpack("n", substr($$bufref, $pos, 2));
      $pos += 2;
    } elsif ($len == 127) {
      return if length($$bufref) < $pos + 8;
      my ($hi, $lo) = unpack("N N", substr($$bufref, $pos, 8));
      $pos += 8;
      if ($hi != 0) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }
      $len = $lo;
    }

    if ($opcode >= 0x8) {
      if (!$fin || $len > 125) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }
    }

    if ($len > $MAX_FRAME_BYTES) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }
    if (!$masked) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }

    return if length($$bufref) < $pos + 4 + $len;

    my $mask = substr($$bufref, $pos, 4); $pos += 4;
    my $payload = substr($$bufref, $pos, $len); $pos += $len;
    substr($$bufref, 0, $pos, '');

    $payload = ws_unmask($payload, $mask);
    $c->{last_activity} = time();

    if ($opcode == 0x8) { conn_close($sel, $c, 0); return; }
    if ($opcode == 0x9) { conn_queue_bytes($c, ws_frame_pong($payload)); next; }
    if ($opcode == 0xA) { $c->{last_pong} = time(); next; }

    if (($opcode == 0x1 || $opcode == 0x2) && $fin && $len == 0) { next; }

    if ($opcode == 0x1 || $opcode == 0x2) {
      if ($c->{frag_active}) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }
      if ($fin) {
        my $obj = ws_try_parse_client_obj($payload);
        if (!$obj) {
          log_ws_malformed(fin=>$fin, opcode=>$opcode, rsv1=>0, masked=>1, len=>$len, payload=>$payload);
          conn_send_ws_err($c, $ERC{MALFORMED});
          next;
        }
        ws_handle_message_obj($c, $obj);
        next;
      } else {
        $c->{frag_active} = 1;
        $c->{frag_opcode} = $opcode;
        $c->{frag_data}   = $payload;
        if (length($c->{frag_data}) > $MAX_MSG_BYTES) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }
        next;
      }
    }

    if ($opcode == 0x0) {
      if (!$c->{frag_active}) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }
      $c->{frag_data} .= $payload;
      if (length($c->{frag_data}) > $MAX_MSG_BYTES) { conn_send_ws_err($c, $ERC{WS_PROTOCOL}); conn_close($sel, $c, 1); return; }
      if ($fin) {
        my $full = $c->{frag_data};
        my $orig = $c->{frag_opcode};
        $c->{frag_active} = 0;
        $c->{frag_opcode} = 0;
        $c->{frag_data}   = '';

        my $obj = ws_try_parse_client_obj($full);
        if (!$obj) {
          log_ws_malformed(fin=>1, opcode=>$orig, rsv1=>0, masked=>1, len=>length($full), payload=>$full);
          conn_send_ws_err($c, $ERC{MALFORMED});
          next;
        }
        ws_handle_message_obj($c, $obj);
      }
      next;
    }

    conn_send_ws_err($c, $ERC{WS_PROTOCOL});
    conn_close($sel, $c, 1);
    return;
  }
}

sub bootstrap_persistence {
  eval { ensure_base_dir(); 1 } or do { log_err("base dir create failed"); $FATAL_PERSISTENCE = 1; return; };
  my $lfh = lock_fh();
  if (!$lfh) { log_err("lock open failed"); $FATAL_PERSISTENCE = 1; return; }
  if (!load_state_locked())   { log_err("state load failed"); $FATAL_PERSISTENCE = 1; close($lfh); return; }
  if (!load_chat_locked())    { log_err("chat load failed (decrypt/parse)"); $FATAL_PERSISTENCE = 1; close($lfh); return; }
  if (!purge_if_due_locked()) { log_err("purge on startup failed"); $FATAL_PERSISTENCE = 1; close($lfh); return; }
  close($lfh);
}
bootstrap_persistence();

my $listen = IO::Socket::INET->new(
  LocalAddr => $LISTEN_HOST,
  LocalPort => $LISTEN_PORT,
  Proto     => 'tcp',
  Listen    => 128,
  ReuseAddr => 1,
) or die "listen failed";
$listen->blocking(0);

my $sel = IO::Select->new($listen);

if ($CORS_ALL) {
  log_err("Novacula-Chat build=$BUILD_ID listening on $LISTEN_HOST:$LISTEN_PORT (CORS: allow-all" . ($DO_NOT_CHECK_IG ? ", IG: bypass" : ", IG: enabled") . ")");
} else {
  my @o = sort keys %CORS_ALLOW;
  log_err("Novacula-Chat build=$BUILD_ID listening on $LISTEN_HOST:$LISTEN_PORT (CORS: allowlist=" . join(",", @o) . ($DO_NOT_CHECK_IG ? ", IG: bypass" : ", IG: enabled") . ")");
}

my $last_periodic_purge_check = time();

while (1) {
  my @ready = $sel->can_read(1);

  for my $fh (@ready) {
    if ($fh == $listen) {
      while (1) {
        my $sock = $listen->accept();
        last if !$sock;
        $sock->blocking(0);
        binmode($sock, ":raw");
        my $fil = fileno($sock);
        $CONN{$fil} = {
          id       => $NEXT_CONN_ID++,
          sock     => $sock,
          state    => 'http',
          inbuf    => '',
          outbuf   => '',
          close_after_write => 0,
          subscribed => 0,
          last_activity => time(),
          last_pong => time(),
          last_ping_sent => 0,
          pending_post => 0,
          pending_worker_pid => undef,
          frag_active => 0,
          frag_opcode => 0,
          frag_data   => '',
        };
        $sel->add($sock);
      }
      next;
    }

    my $fil = fileno($fh);

    if (exists $WORKER{$fil}) {
      my $w = $WORKER{$fil};
      my $buf = '';
      my $n = sysread($fh, $buf, 4096);
      if (!defined $n || $n == 0) {
        my $ok = ($w->{buf} =~ /OK/);
        finish_worker($fil, $ok ? 1 : 0);
        $sel->remove($fh);
        next;
      }
      $w->{buf} .= $buf;
      if ($w->{buf} =~ /\n/) {
        my $ok = ($w->{buf} =~ /OK/);
        finish_worker($fil, $ok ? 1 : 0);
        $sel->remove($fh);
        next;
      }
      next;
    }

    my $c = $CONN{$fil};
    next if !$c;

    my $tmp = '';
    my $n = sysread($fh, $tmp, 8192);
    if (!defined $n) { next; }
    if ($n == 0) { conn_close($sel, $c, 0); next; }
    $c->{inbuf} .= $tmp;

    if ($c->{state} eq 'http') {
      my $req = try_parse_http_req($c);
      next if !defined $req;
      if ($req->{err}) { http_queue_and_close($c, http_err("400 Bad Request", $req->{err}, undef)); next; }

      # CORS preflight (OPTIONS)
      if ($req->{method} eq 'OPTIONS') {
        if ($req->{path} eq '/facebook/users/online-chat/run-challenge' ||
            $req->{path} eq '/facebook/users/online-chat') {
          http_queue_and_close($c, http_preflight_ok($req));
          next;
        }
        http_queue_and_close($c, http_err("404 Not Found", $ERC{MALFORMED}, $req));
        next;
      }

      if ($req->{path} eq '/facebook/users/online-chat/run-challenge') {
        if ($req->{method} eq 'GET')   { http_queue_and_close($c, handle_http_run_challenge_get($req)); next; }
        if ($req->{method} eq 'PATCH') { http_queue_and_close($c, handle_http_run_challenge_patch($req)); next; }
        http_queue_and_close($c, http_err("405 Method Not Allowed", $ERC{MALFORMED}, $req)); next;
      } elsif ($req->{path} eq '/facebook/users/online-chat') {
        my ($ok, $resp_or_err) = handle_ws_upgrade($c, $req);
        if (!$ok) { http_queue_and_close($c, $resp_or_err); next; }
        conn_queue_bytes($c, $resp_or_err);
        $c->{state} = 'ws';
        next;
      } else {
        http_queue_and_close($c, http_err("404 Not Found", $ERC{MALFORMED}, $req));
        next;
      }
    } else {
      ws_process_frames($sel, $c);
      next;
    }
  }

  for my $wf (keys %WORKER) {
    my $w = $WORKER{$wf};
    my $fh = $w->{fh};
    eval { $sel->add($fh) } unless $sel->exists($fh);
    if ((time() - $w->{start}) > 8) {
      kill 9, $w->{pid};
      finish_worker($wf, 0);
      $sel->remove($fh);
    }
  }

  for my $k (keys %CONN) {
    my $c = $CONN{$k};
    next if !$c || $c->{outbuf} eq '';
    my $fh = $c->{sock};
    my $w = syswrite($fh, $c->{outbuf});
    if (defined $w && $w > 0) { substr($c->{outbuf}, 0, $w, ''); }
    if ($c->{state} eq 'http_close' && $c->{close_after_write} && $c->{outbuf} eq '') {
      conn_close($sel, $c, 0);
    }
  }

  my $now = time();

  ig_cache_sweep(0);

  for my $k (keys %CONN) {
    my $c = $CONN{$k};
    next if !$c || $c->{state} ne 'ws';
    if (($now - $c->{last_pong}) > $PONG_TIMEOUT_S) { conn_close($sel, $c, 1); next; }
    if (($now - $c->{last_ping_sent}) >= $PING_INTERVAL_S) {
      $c->{last_ping_sent} = $now;
      conn_queue_bytes($c, ws_frame_ping(''));
    }
  }

  if (($now - $last_periodic_purge_check) >= 60) {
    $last_periodic_purge_check = $now;
    next if $FATAL_PERSISTENCE;
    my $lfh = lock_fh();
    if ($lfh) {
      if (load_state_locked()) {
        if (!purge_if_due_locked()) { log_err("periodic purge failed"); $FATAL_PERSISTENCE = 1; }
      } else { log_err("periodic state load failed"); $FATAL_PERSISTENCE = 1; }
      close($lfh);
    } else { log_err("periodic lock failed"); $FATAL_PERSISTENCE = 1; }
  }
}
