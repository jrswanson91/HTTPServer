#!/usr/bin/env perl

use strict;
use warnings;

my $fixture;
my $setup = 'NULL';
my $teardown = 'NULL';
my $prefix = '';

while (<>) {
    if (m@//#test_fixture\s+(.*)@) {
        $fixture = $1;
    } elsif (m@//#test_setup\s+(.*)@) {
        $setup = $1 ? $1 : 'NULL';
    } elsif (m@//#test_teardown\s+(.*)@) {
        $teardown = $1 ? $1 : 'NULL';
    } elsif (m@//#test_prefix\s+(.*)@) {
        $prefix = $1;
    } elsif (m/^static void test_(\w+)\(/) {
        if ($fixture) {
            print "g_test_add(\"$prefix/$1\", $fixture, NULL, $setup, test_$1, $teardown);\n";
        } else {
            print "g_test_add_func(\"$prefix/$1\", test_$1);\n";
        }
    }
}
