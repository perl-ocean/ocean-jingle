#!/usr/bin/perl
use strict;
use warnings;

# http://tools.ietf.org/html/rfc5769

use feature 'say';

use lib 'lib';
use Ocean::Jingle::STUN::MessageBuilder;
use Ocean::Jingle::STUN::ClassType;
use Ocean::Jingle::STUN::MethodType;
use Ocean::Jingle::STUN::AttributeType;
use Ocean::Jingle::STUN::MessageSigner::ShortTermCredential;
use Ocean::Jingle::STUN::MessageSigner::LongTermCredential;
use Data::Dump qw(dump);

use Ocean::Jingle::ICE::Attribute::ICEControlled;
use Ocean::Jingle::ICE::Attribute::ICEControlling;
use Ocean::Jingle::ICE::Attribute::Priority;
use Ocean::Jingle::STUN::Attribute::Software;
use Ocean::Jingle::STUN::Attribute::Username;
use Ocean::Jingle::STUN::Attribute::XORMappedAddress;
use Ocean::Jingle::STUN::AddressFamilyType;


TEST_01: {

    my $builder = Ocean::Jingle::STUN::MessageBuilder->new(
        class           => Ocean::Jingle::STUN::ClassType::REQUEST,
        method          => Ocean::Jingle::STUN::MethodType::BINDING,
        transaction_id  => q{b7e7a701bc34d686fa87dfae},
        signer          => Ocean::Jingle::STUN::MessageSigner::ShortTermCredential->new( password => 'VOkJxbRl1RmTxUk/WvJxBt' ),
        use_fingerprint => 1,
        padding_byte    => "\x20",
    );

    my $software = Ocean::Jingle::STUN::Attribute::Software->new;
    $software->set(software => q{STUN test client});
    $builder->add_attribute($software);

    my $priority = Ocean::Jingle::ICE::Attribute::Priority->new;
    $priority->set(priority => 1845494271);
    $builder->add_attribute($priority);

    my $ice_controlled = Ocean::Jingle::ICE::Attribute::ICEControlled->new;
    $ice_controlled->set(value => q{932ff9b151263b36});
    $builder->add_attribute($ice_controlled);

    my $username = Ocean::Jingle::STUN::Attribute::Username->new;
    $username->set(username => q{evtj:h6vY});
    $builder->add_attribute($username);


    my $bytes = $builder->build();
    my $result = unpack("H*", $bytes);
    unless ($result eq '000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf') {
        say 'invalid 01';
    } else {
        say 'matched 01';
    }

};

TEST_02: {

    my $builder = Ocean::Jingle::STUN::MessageBuilder->new(
        class           => Ocean::Jingle::STUN::ClassType::RESPONSE_SUCCESS,
        method          => Ocean::Jingle::STUN::MethodType::BINDING,
        transaction_id  => q{b7e7a701bc34d686fa87dfae},
        signer          => Ocean::Jingle::STUN::MessageSigner::ShortTermCredential->new( password => 'VOkJxbRl1RmTxUk/WvJxBt' ),
        use_fingerprint => 1,
        padding_byte    => "\x20",
    );

    my $software = Ocean::Jingle::STUN::Attribute::Software->new;
    $software->set(software => q{test vector});
    $builder->add_attribute($software);

    my $address = Ocean::Jingle::STUN::Attribute::XORMappedAddress->new;
    $address->set(address => q{192.0.2.1});
    $address->set(port => 32853);
    $address->set(family => Ocean::Jingle::STUN::AddressFamilyType::IPV4);
    $builder->add_attribute($address);

    my $bytes = $builder->build();
    my $result = unpack("H*", $bytes);

    unless ($result eq '0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96') {
        say 'invalid 02';
    } else {
        say 'matched 02';
    }
};

TEST_03: {
    my $builder = Ocean::Jingle::STUN::MessageBuilder->new(
        class           => Ocean::Jingle::STUN::ClassType::RESPONSE_SUCCESS,
        method          => Ocean::Jingle::STUN::MethodType::BINDING,
        transaction_id  => q{b7e7a701bc34d686fa87dfae},
        signer          => Ocean::Jingle::STUN::MessageSigner::ShortTermCredential->new( password => 'VOkJxbRl1RmTxUk/WvJxBt' ),
        use_fingerprint => 1,
        padding_byte    => "\x20",
    );

    my $software = Ocean::Jingle::STUN::Attribute::Software->new;
    $software->set(software => q{test vector});
    $builder->add_attribute($software);

    my $address = Ocean::Jingle::STUN::Attribute::XORMappedAddress->new;
    $address->set(address => q{2001:db8:1234:5678:11:2233:4455:6677});
    $address->set(port => 32853);
    $address->set(family => Ocean::Jingle::STUN::AddressFamilyType::IPV6);
    $builder->add_attribute($address);

    my $bytes = $builder->build();
    my $result = unpack("H*", $bytes);

    unless ($result eq '010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c') {
        say 'invalid 03';
    } else {
        say 'matched 03';
    }
};

TEST_04: {
    my $user =  pack("H*","e3839ee38388e383aae38383e382afe382b9");
    say $user;
    my $builder = Ocean::Jingle::STUN::MessageBuilder->new(
        class           => Ocean::Jingle::STUN::ClassType::REQUEST,
        method          => Ocean::Jingle::STUN::MethodType::BINDING,
        transaction_id  => q{78ad3433c6ad72c029da412e},
        use_fingerprint => 0,
        signer          => Ocean::Jingle::STUN::MessageSigner::LongTermCredential->new( 
            password => 'TheMatrIX',
            username => $user,
            realm    => 'example.org',
        ),
    );

    my $username = Ocean::Jingle::STUN::Attribute::Username->new;
    $username->set(username => $user);
    $builder->add_attribute($username);

    my $nonce = Ocean::Jingle::STUN::Attribute::Nonce->new;
    $nonce->set(nonce => q{f//499k954d6OL34oL9FSTvy64sA});
    $builder->add_attribute($nonce);

    my $realm = Ocean::Jingle::STUN::Attribute::Realm->new;
    $realm->set(realm => q{example.org});
    $builder->add_attribute($realm);

    my $bytes = $builder->build();
    my $result = unpack("H*", $bytes);

    unless ($result eq '010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c') {
        say 'invalid 04';
        say $result;
    } else {
        say 'matched 04';
    }
};

