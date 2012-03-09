#!/usr/bin/perl
use strict;
use warnings;

# http://tools.ietf.org/html/rfc5769

use feature 'say';

use lib 'lib';
use Ocean::Jingle::STUN::MessageReader;
use Ocean::Jingle::STUN::MessageVerifier::ShortTermCredential;
use Ocean::Jingle::STUN::MessageVerifier::LongTermCredential;
use Data::Dump qw(dump);

sub read_bytes {
    my $bytearray = shift;
    my $password  = shift;
    my $is_short  = shift;
    my $reader = Ocean::Jingle::STUN::MessageReader->new();
    my $verifier = $is_short 
        ? Ocean::Jingle::STUN::MessageVerifier::ShortTermCredential->new(password => $password)
        : Ocean::Jingle::STUN::MessageVerifier::LongTermCredential->new(password => $password);
    my $bytes = pack('H*', join('', @$bytearray));
    say '=================================================';
    my $msg = $reader->read($bytes);
    say dump($msg);
    if ($verifier->verify($msg)) {
        say 'VALID';
    } else {
        say 'INVALID';
    }
}

sub main {
        
    my @bytes1 = qw(
00 01 00 58
21 12 a4 42
b7 e7 a7 01
bc 34 d6 86
fa 87 df ae
80 22 00 10
53 54 55 4e
20 74 65 73
74 20 63 6c
69 65 6e 74
00 24 00 04
6e 00 01 ff
80 29 00 08
93 2f f9 b1
51 26 3b 36
00 06 00 09
65 76 74 6a
3a 68 36 76
59 20 20 20
00 08 00 14
9a ea a7 0c
bf d8 cb 56
78 1e f2 b5
b2 d3 f2 49
c1 b5 71 a2
80 28 00 04
e5 7a 3b cf
);
    &read_bytes(\@bytes1, 'VOkJxbRl1RmTxUk/WvJxBt', 1);

    my @bytes2 = qw(
01 01 00 3c
21 12 a4 42
b7 e7 a7 01
bc 34 d6 86
fa 87 df ae
80 22 00 0b
74 65 73 74
20 76 65 63
74 6f 72 20
00 20 00 08
00 01 a1 47
e1 12 a6 43
00 08 00 14
2b 91 f5 99
fd 9e 90 c3
8c 74 89 f9
2a f9 ba 53
f0 6b e7 d7
80 28 00 04
c0 7d 4c 96
);
    &read_bytes(\@bytes2, 'VOkJxbRl1RmTxUk/WvJxBt', 1);

    my @bytes3 = qw(
01 01 00 48
21 12 a4 42
b7 e7 a7 01
bc 34 d6 86
fa 87 df ae
80 22 00 0b
74 65 73 74
20 76 65 63
74 6f 72 20
00 20 00 14
00 02 a1 47
01 13 a9 fa
a5 d3 f1 79
bc 25 f4 b5
be d2 b9 d9
00 08 00 14
a3 82 95 4e
4b e6 7b f1
17 84 c9 7c
82 92 c2 75
bf e3 ed 41
80 28 00 04
c8 fb 0b 4c
);
    &read_bytes(\@bytes3, 'VOkJxbRl1RmTxUk/WvJxBt', 1);

    my @bytes4 = qw(
00 01 00 60
21 12 a4 42
78 ad 34 33
c6 ad 72 c0
29 da 41 2e
00 06 00 12
e3 83 9e e3
83 88 e3 83
aa e3 83 83
e3 82 af e3
82 b9 00 00
00 15 00 1c
66 2f 2f 34
39 39 6b 39
35 34 64 36
4f 4c 33 34
6f 4c 39 46
53 54 76 79
36 34 73 41
00 14 00 0b
65 78 61 6d
70 6c 65 2e
6f 72 67 00
00 08 00 14
f6 70 24 65
6d d6 4a 3e
02 b8 e0 71
2e 85 c9 a2
8c a8 96 66
);
    &read_bytes(\@bytes4, 'TheMatrIX', 0);
}

&main();

__END__

