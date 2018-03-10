package Sys::Linux::Syscall::Execve;

use strict;
use warnings;
use Data::Dumper;
use Linux::Seccomp qw/syscall_resolve_name/;
use Encode qw/decode/;

our $VERSION = "0.10";

my $ptr_int_type;
my $ptr_int_size;
my $execve_syscall = syscall_resolve_name('execve');
my $NULL = 0;
my $NULL_PTR = pack($ptr_int_type, $NULL);

BEGIN {
  my $dummy = "dummy";

  my $ptr_str = pack "p",$dummy;
  $ptr_int_size = length $ptr_str;

  if ($ptr_int_size == 8) {
    $ptr_int_type = "Q"; # 64bit pointer size, native endian
  } elsif ($ptr_int_size == 4) {
    $ptr_int_type = "L"; # 32bit pointer size native endian
  } else {
    die "Unknown pointer size $ptr_int_size";
  }
}

our $ERRNO = 0;
our $ERRSTR = "";

sub _execve {
  my ($cmd_ptr, $arg_ptr, $env_ptr) = @_;
  my $ret = syscall $execve_syscall, 0+$cmd_ptr, 0+$arg_ptr, 0+$env_ptr;
  $ERRNO = $!; # Preserve this for posterity.
  $ERRSTR = "$!";
  return $ret;
}

sub get_strptr_int {
  my $ref = shift;
  return unpack($ptr_int_type, _get_str_ptr($ref));
}

sub pack_ptr {
  return pack($ptr_int_type, @_);
}

sub _get_str_ptr {
  my $ref = shift;
  return pack("p", $$ref);
}

sub _build_args {
  my $arg_ref = shift;

  my $buffer = join '', map {_get_str_ptr($_)} @$arg_ref;

  return $buffer . $NULL_PTR; # terminate the char *argv[] with a NULL ptr
}

{
  # Because we have to format things, we have to do some tricks to ensure that perl can't ever garbage collect this data while we might use it.
  my $env_internal;
  sub _build_env {
    my $env_ref = shift;

    my $length =()= keys %$env_ref;

    # This weird buffer is also the start of the char *env[] that will be passed to execve()
    # We're going to put out string data at the end of it, and we're going to need to calculate pointers.
    $env_internal .= $NULL_PTR x ($length+1);

    my @items = map {decode('utf-8', $_ . '=' . $env_ref->{$_})} keys %$env_ref;

    # Start the formatting of things, this is similar to how
    # many C libraries do this.  We take everything and put it in one large buffer
    $env_internal .= join "\0", @items;
    $env_internal .= "\0";

    # ok at this point the buffer is setup in place, with all the right lengths of things.
    my $buf_ptr_origin = get_strptr_int(\$env_internal);
    my $offset = ($length+1) * $ptr_int_size;

    my @ptrs;

    # This all starts at $buf_ptr_origin, and our strings start at +$offset.
    for my $item (@items) {
      push @ptrs, $buf_ptr_origin+$offset;
      $offset += length($item) + 1; # account for \0 at the end of each string
    }

    my $new_ptrs = join '', map {pack_ptr($_)} @ptrs;

    substr $env_internal, 0, length($new_ptrs), $new_ptrs;

    return $env_internal;
  }
}

sub execve_byref {
  my ($cmd_ref, $args_ref, $env_ref) = @_;

  my $_argbuf = _build_args($args_ref//[]);
  my $_envbuf = _build_env($env_ref//{});

  my $arg_ptr = get_strptr_int(\$_argbuf);
  my $env_ptr = get_strptr_int(\$_envbuf);
  my $cmd_ptr = get_strptr_int($cmd_ref);

  my $ret = _execve($cmd_ptr, $arg_ptr, $env_ptr);

  # If we got here, die.  We couldn't execve for some reason
  die "Couldn't execve(): $ret, $ERRNO - $ERRSTR";
}

sub execve_env {
  my ($cmd, $args_ref, $env_ref) = @_;

  execve_byref(\$cmd, $args_ref, $env_ref);
}

sub execve {
  my ($cmd, @args) = @_;

  execve_byref(\$cmd, \@args, \%ENV);
}

print _build_env({foo => "bar", baz => "1....."});

1;
__END__

=pod

=encoding UTF-8

=head1 NAME

Sys::Linux::Syscall::Execve - A raw execve() wrapper that preserves memory addresses

=head1 DESCRIPTION

Due to changes in how exec() works in the upcoming 5.28 to fix [perl #129888] I can no longer expect exec() to preserve the memory address of the arguments provided to it.

Why this weird requirement? It's because I need to preserve that address in order to setup an eBPF program with Seccomp that restricts what can be executed inside a sandbox.

=head1 SHOULD I USE THIS

No.  Perl's built in exec() is better for every use case that you'll ever have.  Not only is it portable, it handles many more edge cases than you can ever expect this to acknowledge even exist.

This is only if you need to restrict the execve() syscall in a Seccomp sandbox.  There are no other possible uses for this.

=head1 EXPORT_OK

=over 1

=item execve

A simple recreation of perl's exec() but using our internal code to execute everything.   However it will never invoke a shell automatically.  This will pass %ENV to the executed program.

=item execve_env

    execve_env("/path/to/cmd", [arg1, arg2, arg3, ...], {env_var => value, ...});

Lets you setup a custom environment to be passed to the new program.  Useful for sanatizing everything for the new program.

=item execve_byref

    my $cmd = "/path/to/cmd";
    my $args = [arg1, arg2, arg3, ...];
    my $env = {env_var => value, ...};

    execve_byref(\$cmd, $args, $env);

This is a special interface, passing the command in as a scalar ref helps ensure that the correct string gets passed by pointer to execve() at the final stage.  This is necessary to be perfectly sure that the correct value is passed to the syscall.

=back

=head1 TODO

=over 1

=item Enable getting the address of arguments and environment variables to be passed also, for extra paranoia


=back

=head1 SEE ALSO

L<App::EvalServerAdvanced>

=head1 AUTHOR

Ryan Voots <simcop@cpan.org>

=cut
