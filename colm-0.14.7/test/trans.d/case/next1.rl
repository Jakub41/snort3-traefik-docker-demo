/*
 * @LANG: indep
 */

int target;

%%{
	machine next1;

	unused := 'unused';

	one := 'one' @{
		print_str "one\n";
		target = fentry(main);
		fnext *target;
	};

	two := 'two' @{
		print_str "two\n";
		target = fentry(main);
		fnext *target;
	};

	main := 
		'1' @{ target = fentry(one); fnext *target; }
	|	'2' @{ target = fentry(two); fnext *target; }
	|	'\n';
}%%

##### INPUT #####
"1one2two1one\n"
##### OUTPUT #####
one
two
one
ACCEPT
