# ============================================================
# src/Network/XKore3.pm  — Final Version
#
# รอรับ connection จาก hybridge.dll ที่ port 6901
# แทนที่จะต่อ RO Server โดยตรง
#
# Frame format (DLL ↔ OpenKore):
#   Byte 0   : direction (0x01=C->S, 0x02=S->C, 0x03=inject)
#   Byte 1   : reserved (0x00)
#   Byte 2-3 : payload_len (unsigned short, little-endian)
#   Byte 4+  : payload
# ============================================================
package Network::XKore3;

use strict;
use base 'Network::DirectConnection';
# สืบทอดจาก DirectConnection เพื่อได้ getState/setState/serverAlive มาฟรี
# แต่เราจะ override method สำคัญทั้งหมดเพื่อเปลี่ยนพฤติกรรม

use IO::Socket::INET;
use IO::Select;

# ── Globals ที่ต้องใช้ทั้งหมด ── ← import ที่นี่ที่เดียว ไม่ใช่ใน sub
use Globals qw($quit %config $net $messageSender $conState);
use Log qw(message warning error debug);
use Network;   # import constants: NOT_CONNECTED, CONNECTED_TO_LOGIN_SERVER, IN_GAME

# ── XKore3 internal state constants ──────────────────────
use constant {
    XKORE3_WAITING   => 0,  # รอ DLL connect มา
    XKORE3_CONNECTED => 1,  # DLL connect แล้ว กำลังทำงาน
};

# ══════════════════════════════════════════════════════════
#  Constructor
# ══════════════════════════════════════════════════════════
sub new {
    my ($class) = @_;

    # สร้าง object เองโดยไม่เรียก SUPER::new
    # เพราะ DirectConnection::new() จะพยายาม connect ไป RO Server ทันที
    # ซึ่งเราไม่ต้องการ เราจะรอ DLL connect มาหาเราแทน
    my $self = bless {}, $class;

    # ── XKore3 state ──
    $self->{xk3_state}   = XKORE3_WAITING;
    $self->{xk3_server}  = undef;    # TCP server socket (จะสร้างใน _startServer)
    $self->{xk3_client}  = undef;    # socket ที่ DLL connect มา
    $self->{xk3_select}  = undef;    # IO::Select สำหรับ non-blocking
    $self->{xk3_recvBuf} = '';       # buffer สะสม bytes ที่ยังไม่ครบ frame

    # ── OpenKore base attributes ── (DirectConnection ต้องการ)
    $self->{host}   = '127.0.0.1';
    $self->{port}   = $config{XKore3Port} || 6901;
    $self->{state}  = Network::NOT_CONNECTED;

    # ── [BUG FIX #4] initialize buffer ก่อนใช้ .= ──
    # ถ้าไม่ initialize Perl จะ warn "Use of uninitialized value"
    $self->{buffer} = '';            # ← OpenKore อ่าน raw bytes จาก key นี้ผ่าน serverRecv()

    $self->_startServer();
    return $self;
}

# ══════════════════════════════════════════════════════════
#  TCP Server Management
# ══════════════════════════════════════════════════════════

sub _startServer {
    my ($self) = @_;
    my $port = $config{XKore3Port} || 6901;

    $self->{xk3_server} = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $port,
        Proto     => 'tcp',
        Listen    => 1,      # DLL มีตัวเดียว queue = 1 พอ
        ReuseAddr => 1,      # restart ได้ทันทีโดยไม่ต้องรอ TIME_WAIT
    );

    if (!$self->{xk3_server}) {
        error "[XKore3] ไม่สามารถเปิด port $port: $!\n";
        $quit = 1;   # แจ้ง OpenKore ให้หยุด เพราะ networking ใช้ไม่ได้
        return;
    }

    # IO::Select ทำให้เราตรวจแบบ non-blocking ได้
    # แทน accept() ซึ่งจะ block main loop ไว้รอ connection
    $self->{xk3_select} = IO::Select->new($self->{xk3_server});

    message "[XKore3] Server เปิดที่ 127.0.0.1:$port รอ hybridge.dll...\n", 'connection';
}

# ══════════════════════════════════════════════════════════
#  OpenKore Required Overrides
#  functions.pl เรียก method เหล่านี้บน $net ทุก main loop
#  ถ้าขาดตัวไหนจะ crash ด้วย "Can't locate object method"
# ══════════════════════════════════════════════════════════

# [BUG FIX #3] ป้องกัน DirectConnection พยายาม reconnect RO Server
# DirectConnection::checkConnection() มี logic "ถ้า NOT_CONNECTED ให้ connect"
# ซึ่งเราไม่ต้องการ เราไม่ได้ต่อ RO Server โดยตรง
sub checkConnection { }

# [BUG FIX #1] OpenKore เรียก serverRecv() ทุก main loop เพื่อดึง packet ใหม่
# เราคืน buffer ที่ DLL ส่งมา (ผ่าน _handleServerPacket) แล้วล้างให้ว่าง
sub serverRecv {
    my ($self) = @_;

    # รับข้อมูลใหม่จาก DLL ก่อน แล้วค่อยคืนทั้งก้อน
    $self->iterate();

    my $data = $self->{buffer};   # ดึง bytes ที่สะสมไว้
    $self->{buffer} = '';         # ล้างรอรับรอบถัดไป
    return $data;
}

# clientRecv: ใน XKore3 เราไม่รับจาก game client โดยตรง คืน undef เสมอ
sub clientRecv { return undef }

# clientAlive: บอกว่า "game client" ยังต่ออยู่ไหม
# ใน XKore3 เราไม่มี client socket ของ game โดยตรง ตรวจจาก DLL แทน
sub clientAlive {
    my ($self) = @_;
    return $self->{xk3_state} == XKORE3_CONNECTED;
}

# serverAlive: บอกว่า "server connection" ยังมีชีวิตไหม
# OpenKore เรียกนี้เพื่อตัดสินว่าควร reconnect หรือเปล่า
sub serverAlive {
    my ($self) = @_;
    return $self->{xk3_state} == XKORE3_CONNECTED;
}

# version: บอก OpenKore ว่าเราเป็น XKore mode แบบไหน
# 0 = standalone, 1 = XKore1, 2 = XKore2
# เราใช้ 0 เพื่อให้ OpenKore ทำงานแบบ standalone AI
sub version { return 0 }

# ══════════════════════════════════════════════════════════
#  Main Loop iterate()
#  ถูกเรียกผ่าน serverRecv → iterate() ทุก main loop
# ══════════════════════════════════════════════════════════

sub iterate {
    my ($self) = @_;

    if ($self->{xk3_state} == XKORE3_WAITING) {
        $self->_checkForNewConnection();
    } elsif ($self->{xk3_state} == XKORE3_CONNECTED) {
        $self->_readFromDLL();
    }
}

sub _checkForNewConnection {
    my ($self) = @_;

    return unless $self->{xk3_select}->can_read(0);

    my $client = $self->{xk3_server}->accept();
    return unless $client;

    $self->{xk3_client} = $client;
    $self->{xk3_state}  = XKORE3_CONNECTED;
    $self->{xk3_select}->add($client);

    message "[XKore3] hybridge.dll เชื่อมต่อมาแล้ว!\n", 'connection';

    # ── Initialize packetParser ──────────────────────────────────
    # ดึง $packetParser, $incomingMessages, $outgoingClientMessages จาก Globals
    # $serverType ไม่ได้อยู่ใน export list ต้องเข้าถึงผ่าน $Globals::serverType แทน
    use Globals qw($packetParser $incomingMessages $outgoingClientMessages);
    use Network::MessageTokenizer;
    use Globals qw(%rpackets);

    # เข้าถึง $serverType ผ่านชื่อ package เต็ม เพราะ Globals ไม่ export มัน
    # ค่าจาก config.txt จะถูกเซ็ตไว้ใน $Globals::serverType โดยอัตโนมัติ
    $Globals::serverType = $config{serverType} || 0;

    message "[XKore3] ใช้ serverType=$Globals::serverType\n", 'connection';

    # สร้าง packetParser สำหรับ parse S->C packet ทุกตัว
    # Network::Receive->create() โหลด handler ที่เหมาะสมกับ serverType
    eval {
        $packetParser = Network::Receive->create($Globals::serverType);
    };
    if ($@ || !$packetParser) {
        warning "[XKore3] serverType=$Globals::serverType ไม่รองรับ ลอง 0 แทน\n";
        eval { $packetParser = Network::Receive->create(0); };
    }

    if (!$packetParser) {
        error "[XKore3] สร้าง packetParser ไม่ได้ — ตรวจสอบ serverType\n";
        $self->_disconnect();
        return;
    }

    # สร้าง MessageTokenizer สำหรับแบ่ง packet ที่มาใน TCP stream
    # เพราะ TCP อาจส่ง packet หลายตัวมาติดกัน tokenizer จะแยกให้ถูกต้อง
    $incomingMessages       = Network::MessageTokenizer->new(\%rpackets);
    $outgoingClientMessages = Network::MessageTokenizer->new(\%rpackets);

    message "[XKore3] packetParser พร้อมแล้ว!\n", 'connection';

    $self->{state} = Network::CONNECTED_TO_LOGIN_SERVER;
    $conState = 1;
}

sub _readFromDLL {
    my ($self) = @_;

    return unless $self->{xk3_select}->can_read(0);

    my $data;
    my $bytesRead = $self->{xk3_client}->sysread($data, 65536);

    if (!defined $bytesRead || $bytesRead == 0) {
        message "[XKore3] hybridge.dll ตัดการเชื่อมต่อ\n", 'connection';
        $self->_disconnect();
        return;
    }

    $self->{xk3_recvBuf} .= $data;
    $self->_parseFrames();
}

sub _parseFrames {
    my ($self) = @_;

    while (length($self->{xk3_recvBuf}) >= 4) {

        # unpack 'CCv': C=unsigned byte, C=unsigned byte, v=unsigned short LE
        my ($direction, $reserved, $payloadLen) =
            unpack('CCv', substr($self->{xk3_recvBuf}, 0, 4));

        if ($payloadLen <= 0 || $payloadLen > 65535) {
            warning "[XKore3] payloadLen=$payloadLen ผิดปกติ → disconnect\n";
            $self->_disconnect();
            return;
        }

        # ยังได้ payload ไม่ครบ → รอรับใน iteration ถัดไป
        last if length($self->{xk3_recvBuf}) < 4 + $payloadLen;

        my $payload = substr($self->{xk3_recvBuf}, 4, $payloadLen);
        substr($self->{xk3_recvBuf}, 0, 4 + $payloadLen) = '';

        if ($direction == 0x02) {
            # S->C: packet จาก RO Server ที่ DLL relay มา
            # เพิ่มเข้า $self->{buffer} เพื่อให้ OpenKore parse
            $self->{buffer} .= $payload;
            debug sprintf("[XKore3] S->C OP:0x%04X len:%d\n",
                unpack('v', $payload), $payloadLen), 'xkore3';

        } elsif ($direction == 0x01) {
            # C->S: packet ที่ player กดเองใน game (DLL forward มา)
            # แค่ log ไว้ ไม่ต้องทำอะไร
            debug sprintf("[XKore3] C->S OP:0x%04X len:%d (player action)\n",
                unpack('v', $payload), $payloadLen), 'xkore3';
        }
    }
}

# ══════════════════════════════════════════════════════════
#  Sending
# ══════════════════════════════════════════════════════════

# [BUG FIX #2] serverSend: OpenKore AI เรียกผ่าน $messageSender->sendToServer()
# เพิ่ม alias ให้ทั้ง serverSend และ clientSend ชี้ไปที่ _sendInject เดียวกัน
sub _sendInject {
    my ($self, $data) = @_;

    return unless $self->{xk3_state} == XKORE3_CONNECTED;
    return unless $self->{xk3_client};
    return unless defined $data && length($data) > 0;

    # ห่อ packet ด้วย frame header แล้วส่งกลับไปให้ DLL inject เข้า game
    # 0x03 = inject เข้า game client ในฐานะ C->S
    my $len   = length($data);
    my $frame = pack('CCv', 0x03, 0x00, $len) . $data;

    my $sent = $self->{xk3_client}->syswrite($frame);
    if (!defined $sent) {
        warning "[XKore3] inject send failed: $!\n";
        $self->_disconnect();
    }
}

# ทั้งสอง method ชี้ไปที่ _sendInject เดียวกัน
*serverSend = \&_sendInject;   # ← OpenKore AI ใช้ method นี้
*clientSend = \&_sendInject;   # ← บาง version ใช้ method นี้

# ══════════════════════════════════════════════════════════
#  Disconnect Cleanup
# ══════════════════════════════════════════════════════════

sub _disconnect {
    my ($self) = @_;

    if ($self->{xk3_client}) {
        $self->{xk3_select}->remove($self->{xk3_client});
        $self->{xk3_client}->close();
        $self->{xk3_client} = undef;
    }

    $self->{xk3_state}   = XKORE3_WAITING;
    $self->{xk3_recvBuf} = '';
    $self->{buffer}      = '';   # ล้าง OpenKore packet buffer ด้วย
    $self->{state}       = Network::NOT_CONNECTED;

    message "[XKore3] รอ hybridge.dll reconnect...\n", 'connection';
}

sub DESTROY {
    my ($self) = @_;
    $self->_disconnect();
    $self->{xk3_server}->close() if $self->{xk3_server};
}

sub serverDisconnect {
    my ($self) = @_;
    # ใน XKore3 เราไม่ disconnect จาก RO Server โดยตรง
    # แค่ reset state ให้กลับไปรอ DLL ใหม่
    $self->_disconnect();
}

1;
