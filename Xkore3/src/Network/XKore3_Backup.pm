# ============================================================
# src/Network/XKore3.pm
#
# โหมดนี้ทำตัวเป็น TCP Server รอ hybridge.dll connect มา
# แทนที่จะต่อ RO Server เอง
#
# เปรียบเหมือน: OpenKore นั่งอยู่ที่โต๊ะ รอโทรศัพท์จาก DLL
# เมื่อ DLL โทรมา OpenKore ก็คุยกับมันแทนที่จะโทรหา server เอง
# ============================================================
package Network::XKore3;

use strict;
use base 'Network::DirectConnection';  
# สืบทอดจาก DirectConnection เพื่อได้ method พื้นฐานมาฟรี
# เช่น getState(), setState() และ utility functions ต่างๆ
# เราจะ override เฉพาะที่ต้องการเปลี่ยนพฤติกรรม

use IO::Socket::INET;    # สำหรับสร้าง TCP server socket
use IO::Select;          # สำหรับ non-blocking I/O check
use Scalar::Util qw(blessed);

# import Globals ที่จำเป็น
use Globals qw($quit %config $net $messageSender);
use Log qw(message warning error debug);
use Utils::Exceptions;

# ── State Constants ───────────────────────────────────────
# เราใช้ state เพื่อติดตามว่าตอนนี้อยู่ในสถานะไหน
# แทนที่จะใช้ 0/1/2 ตรงๆ ซึ่งอ่านยาก
use constant {
    XKORE3_WAITING    => 0,  # รอ hybridge.dll connect มา
    XKORE3_CONNECTED  => 1,  # DLL connect มาแล้ว กำลังทำงาน
};

sub _flushSendQueue {
    # placeholder สำหรับ Phase ถัดไป
    # เมื่อมีระบบ queue ก็ค่อยเพิ่ม logic
}

# ── Constructor ──────────────────────────────────────────
sub new {
    my ($class) = @_;
    # สร้าง hash เปล่าๆ เป็น base object
    # ไม่ต้องเรียก SUPER::new เพราะไม่ต้องการ connect RO Server
    my $self = bless {}, $class;
    
    $self->{xk3_state}   = XKORE3_WAITING;
    $self->{xk3_server}  = undef;
    $self->{xk3_client}  = undef;
    $self->{xk3_select}  = undef;
    $self->{xk3_recvBuf} = '';
    
    # OpenKore ต้องการ attribute เหล่านี้จาก Network base class
    $self->{host}  = undef;
    $self->{port}  = undef;
    $self->{state} = Network::NOT_CONNECTED;  # state ของ OpenKore
    
    $self->_startServer();
    return $self;
}

# ── เปิด TCP Server ────────────────────────────────────────
# private method (ขึ้นต้นด้วย _ หมายถึง internal ใช้ภายใน class เท่านั้น)
sub _startServer {
    my ($self) = @_;
    
    my $port = $config{XKore3Port} || 6901;  # อ่านจาก config หรือใช้ default 6901
    
    # สร้าง TCP server socket
    # ReuseAddr = 1 สำคัญมาก: ถ้าไม่ใส่ การ restart OpenKore ภายใน 2 นาที
    # จะเจอ error "Address already in use" เพราะ OS ยังถือ port เดิมอยู่
    $self->{xk3_server} = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $port,
        Proto     => 'tcp',
        Listen    => 1,       # queue รอ connection ได้ 1 ตัว
        ReuseAddr => 1,
    );
    
    if (!$self->{xk3_server}) {
        # ถ้าเปิด port ไม่ได้ (อาจมีโปรแกรมอื่นใช้อยู่) ให้แจ้งและหยุด
        error "[XKore3] ไม่สามารถเปิด port $port: $!\n";
        error "[XKore3] ตรวจสอบว่าไม่มีโปรแกรมอื่นใช้ port นี้อยู่\n";
        return;
    }
    
    # สร้าง IO::Select เพื่อทำ non-blocking check
    # เหตุผล: ถ้าใช้ accept() ตรงๆ โปรแกรมจะ "หยุด" รอ connection
    # แต่ถ้าใช้ IO::Select เราถามได้ว่า "มีใคย connect มาไหม?" โดยไม่ต้องรอ
    # ทำให้ OpenKore AI ยังทำงานได้ต่อเนื่องระหว่างรอ DLL
    $self->{xk3_select} = IO::Select->new($self->{xk3_server});
    
    message "[XKore3] Server เปิดที่ 127.0.0.1:$port — รอ hybridge.dll...\n", 'connection';
}

# ── iterate() — ถูกเรียกทุก main loop iteration ──────────
# นี่คือ "หัวใจเต้น" ของ network mode
# OpenKore เรียก method นี้ซ้ำๆ เพื่อ:
#   1. ตรวจว่ามี connection ใหม่จาก DLL ไหม
#   2. อ่าน packet ที่ DLL ส่งมา
#   3. ส่ง packet ที่ AI สั่งออกไป
sub iterate {
    my ($self) = @_;
    
    # ── กรณีที่ 1: ยังไม่มี DLL connect ──
    if ($self->{xk3_state} == XKORE3_WAITING) {
        $self->_checkForNewConnection();
        return;  # ยังไม่มีอะไรทำ รอไปก่อน
    }
    
    # ── กรณีที่ 2: DLL connect อยู่แล้ว ──
    if ($self->{xk3_state} == XKORE3_CONNECTED) {
        $self->_readFromDLL();   # อ่าน packet จาก DLL
        $self->_flushSendQueue(); # ส่ง packet ที่ค้างอยู่
    }
}

# ── ตรวจว่า DLL connect มาหรือยัง ────────────────────────
sub _checkForNewConnection {
    my ($self) = @_;
    
    # can_read(0) = ถามแบบ non-blocking
    # 0 = timeout 0 วินาที หมายถึง "ถ้าไม่มีก็ออกไปเลย"
    return unless $self->{xk3_select}->can_read(0);
    
    # มีคน connect มา! รับ connection
    my $client = $self->{xk3_server}->accept();
    return unless $client;
    
    $self->{xk3_client} = $client;
    $self->{xk3_state}  = XKORE3_CONNECTED;
    
    # เพิ่ม client socket เข้า selector ด้วย
    # เพื่อให้ตรวจสอบว่ามีข้อมูลรอได้
    $self->{xk3_select}->add($client);
    
    message "[XKore3] hybridge.dll เชื่อมต่อมาแล้ว! พร้อมรับ packet\n", 'connection';
    
    # แจ้ง OpenKore ว่า "เราเชื่อมต่อแล้ว" เพื่อให้ AI เริ่มทำงาน
    # conState คือ state machine ของ OpenKore ที่ติดตามว่าอยู่ขั้นตอนไหน
    # 1 = connected to login server, 2 = logged in, ฯลฯ
    # เราตั้งเป็น 1 ก่อน แล้วรอดู packet จริงค่อยอัพเดต
    use Globals qw($conState);
    $conState = 1;
}

# ── อ่าน framed packet จาก DLL ────────────────────────────
sub _readFromDLL {
    my ($self) = @_;
    
    # ตรวจว่ามีข้อมูลรอหรือเปล่า (non-blocking)
    return unless $self->{xk3_select}->can_read(0);
    
    # อ่านข้อมูลเข้า buffer
    my $data;
    my $bytesRead = $self->{xk3_client}->sysread($data, 65536);
    
    # DLL ปิด connection
    if (!defined $bytesRead || $bytesRead == 0) {
        message "[XKore3] hybridge.dll ตัดการเชื่อมต่อ\n", 'connection';
        $self->_disconnect();
        return;
    }
    
    # สะสมข้อมูลลง buffer ก่อน
    # เหตุผล: TCP อาจส่งมาแค่ครึ่ง frame หรือส่งมาหลาย frame รวมกันก็ได้
    # เราต้องสะสมจนได้ครบ 1 frame แล้วค่อย parse
    $self->{xk3_recvBuf} .= $data;
    
    # parse frame ออกจาก buffer วนซ้ำจนหมด
    $self->_parseFrames();
}

# ── Parse framed packets จาก buffer ──────────────────────
# Frame format: [dir:1][rsv:1][len:2][payload:len]
sub _parseFrames {
    my ($self) = @_;
    
    # วน loop จนกว่า buffer จะไม่มี frame ครบอีกต่อไป
    while (length($self->{xk3_recvBuf}) >= 4) {
        
        # อ่าน header 4 bytes แรก
        # 'C' = unsigned char (1 byte), 'v' = unsigned short little-endian (2 bytes)
        my ($direction, $reserved, $payloadLen) =
            unpack('CCv', substr($self->{xk3_recvBuf}, 0, 4));
        
        # ตรวจ payloadLen สมเหตุสมผลไหม
        if ($payloadLen <= 0 || $payloadLen > 65535) {
            warning "[XKore3] payloadLen=$payloadLen ผิดปกติ ตัด connection\n";
            $self->_disconnect();
            return;
        }
        
        # ยังได้ payload ไม่ครบ รอก่อน
        last if length($self->{xk3_recvBuf}) < 4 + $payloadLen;
        
        # ตัด 1 frame ออกจาก buffer
        my $payload = substr($self->{xk3_recvBuf}, 4, $payloadLen);
        substr($self->{xk3_recvBuf}, 0, 4 + $payloadLen) = '';
        
        # ส่งให้ OpenKore ประมวลผลตาม direction
        if ($direction == 0x02) {
            # S->C: packet จาก RO Server ที่ DLL盗傍 → ส่งให้ OpenKore เข้าใจ state ของเกม
            $self->_handleServerPacket($payload);
        } elsif ($direction == 0x01) {
            # C->S: packet ที่ player กดเองใน game → แค่ log ดู ไม่ต้องทำอะไร
            debug "[XKore3] C->S packet len=$payloadLen\n", 'xkore3';
        }
        # 0x03 = inject ส่งมาจาก Xkore3 ไปหา DLL ไม่ควรจะรับกลับมา
    }
}

# ── ส่ง packet ที่ OpenKore AI สั่งออกไป ──────────────────
# OpenKore AI เรียก method นี้เมื่อต้องการส่ง C->S packet
# เช่น WALK, ATTACK, USE_SKILL, CHAT ฯลฯ
sub clientSend {
    my ($self, $data) = @_;
    
    return unless $self->{xk3_state} == XKORE3_CONNECTED;
    return unless $self->{xk3_client};
    
    # ห่อด้วย frame header แล้วส่งกลับไปให้ DLL inject เข้า game
    # direction 0x03 = "inject นี้เข้า game ในฐานะ C->S"
    my $len   = length($data);
    my $frame = pack('CCv', 0x03, 0x00, $len) . $data;
    #                  ^dir  ^rsv  ^len little-endian
    
    $self->{xk3_client}->syswrite($frame);
}

# ── จัดการ Server Packet → ส่งให้ OpenKore parse ──────────
sub _handleServerPacket {
    my ($self, $payload) = @_;
    $self->{buffer} .= $payload;   # ← ชื่อที่ OpenKore เข้าใจ
}

# ── Disconnect cleanup ─────────────────────────────────────
sub _disconnect {
    my ($self) = @_;
    
    if ($self->{xk3_client}) {
        $self->{xk3_select}->remove($self->{xk3_client});
        $self->{xk3_client}->close();
        $self->{xk3_client} = undef;
    }
    
    $self->{xk3_state}   = XKORE3_WAITING;
    $self->{xk3_recvBuf} = '';  # ล้าง buffer
    
    message "[XKore3] รอ hybridge.dll connect ใหม่...\n", 'connection';
}

1;  # Perl module ต้องจบด้วย 1 เสมอ