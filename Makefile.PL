use strict;
use warnings;

use inc::Module::Install;

name 'Ocean-Jingle';
all_from 'lib/Ocean/Jingle.pm';

requires(
    Ocean => '0.01',

    'AnyEvent::Handle::UDP'     => 0.032,
    'Tie::Hash::Indexed'        => 0.05,
    'Authen::SASL::SASLprep'    => 1.01,
);

tests('t/*.t t/*/*.t t/*/*/*.t');

author_tests('xt');

test_requires(
    #'Test::Class' => 0,
    'Test::More'                => 0,
    'Test::LoadAllModules'      => '',
    'TAP::Harness::JUnit'       => '',
);

install_script 'bin/ocean-stun';
install_script 'bin/ocean-turn';

auto_include;
WriteAll;
