//
// @LANG: julia
// @GENERATED: true
//


%%{
	machine gotocallret;

	# A reference to a state in an unused action caused a segfault in 5.8. */
	action unusedAction {fentry(garble_line);
}

	action err_garbling_line {print( "error: garbling line\n" );
}
	action goto_main {fnext main;}
	action recovery_failed {print( "error: failed to recover\n" );
}

	# Error machine, consumes to end of 
	# line, then starts the main line over.
	garble_line := ( (any-'\n')*'\n') 
		>err_garbling_line
		@goto_main
		$/recovery_failed;

	action hold_and_return {fhold;fnret;}

	# Look for a string of alphas or of digits, 
	# on anything else, hold the character and return.
	alp_comm := alpha+ $!hold_and_return;
	dig_comm := digit+ $!hold_and_return;

	# Choose which to machine to call into based on the command.
	action comm_arg {if ( comm >= 97 )
	fncall alp_comm;
else
	fncall dig_comm;
end
}

	# Specifies command string. Note that the arg is left out.
	command = (
		[a-z0-9] @{comm = fc;
} ' ' @comm_arg @{print( "prints\n" );
} '\n'
	) @{print( "correct command\n" );
};

	# Any number of commands. If there is an 
	# error anywhere, garble the line.
	main := command* $!{fhold;fnext garble_line;}; 
}%%



%% write data;

function m( data::AbstractString )
	p = 0
	pe = length(data)
	eof = length(data)
	cs = 0
	buffer = ""
comm = 0;
top = 0;
stack = Int [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];

	%% write init;
	%% write exec;

	if ( cs >= gotocallret_first_final )
		println( "ACCEPT" );
	else
		println( "FAIL" );
	end
end

	m( "lkajsdf\n" );
	m( "2134\n" );
	m( "(\n" );
	m( "\n" );
	m( "*234234()0909 092 -234aslkf09`1 11\n" );
	m( "1\n" );
	m( "909\n" );
	m( "1 a\n" );
	m( "11 1\n" );
	m( "a 1\n" );
	m( "aa a\n" );
	m( "1 1\n" );
	m( "1 123456\n" );
	m( "a a\n" );
	m( "a abcdef\n" );
	m( "h" );
	m( "a aa1" );
