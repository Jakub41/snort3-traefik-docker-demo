/*
 * @LANG: csharp
 * @GENERATED: true
 */

using System;
// Disables lots of warnings that appear in the test suite
#pragma warning disable 0168, 0169, 0219, 0162, 0414
namespace Test {
class Test
{
int ts;
int te;
int act;
int token;

%%{
	machine scanner;

	# Warning: changing the patterns or the input string will affect the
	# coverage of the scanner action types.
	main := |*
		'a' => {Console.Write( "on last     " );if ( p + 1 == te )
{
	Console.Write( "yes" );
} 
Console.Write( "\n" );};

		'b'+ => {Console.Write( "on next     " );if ( p + 1 == te )
{
	Console.Write( "yes" );
} 
Console.Write( "\n" );};

		'c1' 'dxxx'? => {Console.Write( "on lag      " );if ( p + 1 == te )
{
	Console.Write( "yes" );
} 
Console.Write( "\n" );};

		'd1' => {Console.Write( "lm switch1  " );if ( p + 1 == te )
{
	Console.Write( "yes" );
} 
Console.Write( "\n" );};
		'd2' => {Console.Write( "lm switch2  " );if ( p + 1 == te )
{
	Console.Write( "yes" );
} 
Console.Write( "\n" );};

		[d0-9]+ '.';

		'\n';
	*|;
}%%


%% write data;
int cs;

void init()
{
	%% write init;
}

void exec( char[] data, int len )
{
	int p = 0;
	int pe = len;
	int eof = len;
	string _s;
	char [] buffer = new char [1024];
	int blen = 0;
	%% write exec;
}

void finish( )
{
	if ( cs >= scanner_first_final )
		Console.WriteLine( "ACCEPT" );
	else
		Console.WriteLine( "FAIL" );
}

static readonly string[] inp = {
"abbc1d1d2\n",
};


static readonly int inplen = 1;

public static void Main (string[] args)
{
	Test machine = new Test();
	for ( int i = 0; i < inplen; i++ ) {
		machine.init();
		machine.exec( inp[i].ToCharArray(), inp[i].Length );
		machine.finish();
	}
}
}
}
