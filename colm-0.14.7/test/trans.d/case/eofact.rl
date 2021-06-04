/*
 * @LANG: indep
 * @NEEDS_EOF: yes
 *
 * Test works with split code gen.
 */

%%{
	machine eofact;

	action a1 { print_str "a1\n"; }
	action a2 { print_str "a2\n"; }
	action a3 { print_str "a3\n"; }
	action a4 { print_str "a4\n"; }


	main := (
		'hello' @eof a1 %eof a2 '\n'? |
		'there' @eof a3 %eof a4
	);

}%%

##### INPUT #####
""
"h"
"hell"
"hello"
"hello\n"
"t"
"ther"
"there"
"friend"
##### OUTPUT #####
a1
a3
FAIL
a1
FAIL
a1
FAIL
a2
ACCEPT
ACCEPT
a3
FAIL
a3
FAIL
a4
ACCEPT
FAIL
