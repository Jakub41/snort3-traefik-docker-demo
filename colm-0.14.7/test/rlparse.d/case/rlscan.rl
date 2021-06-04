/*
 *  Copyright 2006-2007 Adrian Thurston <thurston@complang.org>
 *  Copyright 2011 Josef Goettgens
 */

/*  This file is part of Ragel.
 *
 *  Ragel is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 * 
 *  Ragel is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with Ragel; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#include <iostream>
#include <fstream>
#include <string.h>

#include "ragel.h"
#include "rlscan.h"
#include "inputdata.h"

//#define LOG_TOKENS

using std::ifstream;
using std::istream;
using std::ostream;
using std::endl;

enum InlineBlockType
{
	CurlyDelimited,
	SemiTerminated
};

char *newTokdata( int toklen )
{
	char *tokdata = new char[sizeof(TokHead) + toklen + 1];
	return tokdata + sizeof(TokHead);
}

void deleteTokdata( char *tokdata )
{
	if ( tokdata )
		delete[] ( tokdata - sizeof(TokHead) );
}

void linkTokdata( Parser6 *parser, char *tokdata )
{
	TokHead *head = (TokHead*)( tokdata - sizeof(TokHead) );
	head->next = parser->tokHead;
	parser->tokHead = head;
}

void clearTokdata( Parser6 *parser )
{
	while ( parser->tokHead != 0 ) {
		TokHead *next = parser->tokHead->next;
		delete[] (char*)parser->tokHead;
		parser->tokHead = next;
	}
}

/*
 * The Scanner for Importing
 */

%%{
	machine inline_token_scan;
	alphtype int;
	access tok_;

	# Import scanner tokens.
	import "rlparse.h"; 

	main := |*
		# Define of number.
		IMP_Define IMP_Word IMP_UInt => { 
			int base = tok_ts - token_data;
			int nameOff = 1;
			int numOff = 2;

			directToParser( inclToParser, fileName, line, column, TK_Word, 
					token_strings[base+nameOff], token_lens[base+nameOff] );
			directToParser( inclToParser, fileName, line, column, '=', 0, 0 );
			directToParser( inclToParser, fileName, line, column, TK_UInt,
					token_strings[base+numOff], token_lens[base+numOff] );
			directToParser( inclToParser, fileName, line, column, ';', 0, 0 );
		};

		# Assignment of number.
		IMP_Word '=' IMP_UInt => { 
			int base = tok_ts - token_data;
			int nameOff = 0;
			int numOff = 2;

			directToParser( inclToParser, fileName, line, column, TK_Word, 
					token_strings[base+nameOff], token_lens[base+nameOff] );
			directToParser( inclToParser, fileName, line, column, '=', 0, 0 );
			directToParser( inclToParser, fileName, line, column, TK_UInt,
					token_strings[base+numOff], token_lens[base+numOff] );
			directToParser( inclToParser, fileName, line, column, ';', 0, 0 );
		};

		# Define of literal.
		IMP_Define IMP_Word IMP_Literal => { 
			int base = tok_ts - token_data;
			int nameOff = 1;
			int litOff = 2;

			directToParser( inclToParser, fileName, line, column, TK_Word, 
					token_strings[base+nameOff], token_lens[base+nameOff] );
			directToParser( inclToParser, fileName, line, column, '=', 0, 0 );
			directToParser( inclToParser, fileName, line, column, TK_Literal,
					token_strings[base+litOff], token_lens[base+litOff] );
			directToParser( inclToParser, fileName, line, column, ';', 0, 0 );
		};

		# Assignment of literal.
		IMP_Word '=' IMP_Literal => { 
			int base = tok_ts - token_data;
			int nameOff = 0;
			int litOff = 2;

			directToParser( inclToParser, fileName, line, column, TK_Word, 
					token_strings[base+nameOff], token_lens[base+nameOff] );
			directToParser( inclToParser, fileName, line, column, '=', 0, 0 );
			directToParser( inclToParser, fileName, line, column, TK_Literal,
					token_strings[base+litOff], token_lens[base+litOff] );
			directToParser( inclToParser, fileName, line, column, ';', 0, 0 );
		};

		# Catch everything else.
		any;
	*|;
}%%

%% write data;

void Scanner::flushImport()
{
	int *p = token_data;
	int *pe = token_data + cur_token;
	int *eof = 0;

	%%{
		machine inline_token_scan;
		write init;
		write exec;
	}%%

	if ( tok_ts == 0 )
		cur_token = 0;
	else {
		cur_token = pe - tok_ts;
		int ts_offset = tok_ts - token_data;
		memmove( token_data, token_data+ts_offset, cur_token*sizeof(token_data[0]) );
		memmove( token_strings, token_strings+ts_offset, cur_token*sizeof(token_strings[0]) );
		memmove( token_lens, token_lens+ts_offset, cur_token*sizeof(token_lens[0]) );
	}
}

void Scanner::directToParser( Parser6 *toParser, const char *tokFileName, int tokLine, 
		int tokColumn, int type, char *tokdata, int toklen )
{
	InputLoc loc;

	#ifdef LOG_TOKENS
	cerr << "scanner:" << tokLine << ":" << tokColumn << 
			": sending token to the parser " << Parser6_lelNames[type];
	cerr << " " << toklen;
	if ( tokdata != 0 )
		cerr << " " << tokdata;
	cerr << endl;
	#endif

	loc.fileName = tokFileName;
	loc.line = tokLine;
	loc.col = tokColumn;

	toParser->token( loc, type, tokdata, toklen );
}

void Scanner::importToken( int token, char *start, char *end )
{
	if ( cur_token == max_tokens )
		flushImport();

	token_data[cur_token] = token;
	if ( start == 0 ) {
		token_strings[cur_token] = 0;
		token_lens[cur_token] = 0;
	}
	else {
		int toklen = end-start;
		token_lens[cur_token] = toklen;
		token_strings[cur_token] = new char[toklen+1];
		memcpy( token_strings[cur_token], start, toklen );
		token_strings[cur_token][toklen] = 0;
	}
	cur_token++;
}

void Scanner::pass()
{
	if ( sectionPass )
		return;

	updateCol();

	/* If no errors and we are at the bottom of the include stack (the
	 * source file listed on the command line) then write out the data. */
	if ( includeDepth == 0 && id->machineSpec == 0 && id->machineName == 0 )
		id->curItem->data.write( ts, te-ts );
}

void Scanner::pass( int token, char *start, char *end )
{
	if ( sectionPass )
		return;

	if ( importMachines )
		importToken( token, start, end );

	pass();
}

/*
 * The scanner for processing sections, includes, imports, etc.
 */

%%{
	machine section_parse;
	alphtype int;
	write data;
}%%

void Scanner::init( )
{
	%% write init;
}

bool Scanner::active()
{
	if ( ignoreSection )
		return false;

	if ( parser == 0 && ! parserExistsError ) {
		id->error(scan_loc()) << "this specification has no name, nor does any previous"
			" specification" << endl;
		parserExistsError = true;
	}

	if ( parser == 0 )
		return false;

	return true;
}

InputLoc Scanner::scan_loc()
{
	return makeInputLoc( fileName, line, column );
}

void Scanner::updateCol()
{
	char *from = lastnl;
	if ( from == 0 )
		from = ts;
	column += te - from;
	lastnl = 0;
}

void Scanner::handleMachine()
{
	if ( sectionPass ) {
		/* Assign a name to the machine. */
		char *machine = word;

		SectionDictEl *sdEl = id->sectionDict.find( machine );
		if ( sdEl == 0 ) {
			sdEl = new SectionDictEl( machine );
			sdEl->value = new Section( machine );
			id->sectionDict.insert( sdEl );
		}

		section = sdEl->value;
	}
	else {

		/* Assign a name to the machine. */
		char *machine = word;

		if ( !importMachines && inclSectionTarg == 0 ) {
			ignoreSection = false;

			ParserDictEl *pdEl = id->parserDict.find( machine );
			if ( pdEl == 0 ) {
				pdEl = new ParserDictEl( machine );
				pdEl->value = new Parser6( id, fileName, machine, sectionLoc,
						id->hostLang, id->minimizeLevel, id->minimizeOpt );
				pdEl->value->init();
				id->parserDict.insert( pdEl );
				id->parserList.append( pdEl->value );

				/* Also into the parse data dict. This is the new style. */
				ParseDataDictEl *pddEl = new ParseDataDictEl( machine );
				pddEl->value = pdEl->value->pd;
				id->parseDataDict.insert( pddEl );
				id->parseDataList.append( pddEl->value );
			}

			parser = pdEl->value;
		}
		else if ( !importMachines && strcmp( inclSectionTarg, machine ) == 0 ) {
			/* found include target */
			ignoreSection = false;
			parser = inclToParser;
		}
		else {
			/* ignoring section */
			ignoreSection = true;
			parser = 0;
		}
	}
}

void Scanner::handleInclude()
{
	if ( sectionPass )
		return;

	if ( active() ) {
		char *inclSectionName = word;
		const char **includeChecks = 0;

		/* Implement defaults for the input file and section name. */
		if ( inclSectionName == 0 )
			inclSectionName = parser->sectionName;

		if ( lit != 0 ) {
			long length = 0;
			bool caseInsensitive = false;
			char *data = prepareLitString( id, InputLoc(), lit, lit_len, length, caseInsensitive );

			includeChecks = parser->pd->id->makeIncludePathChecks( fileName, data );
		}
		else {
			char *test = new char[strlen(fileName)+1];
			strcpy( test, fileName );

			includeChecks = new const char*[2];

			includeChecks[0] = test;
			includeChecks[1] = 0;
		}

		long found = 0;
		ifstream *inFile = parser->pd->id->tryOpenInclude( includeChecks, found );
		if ( inFile == 0 ) {
			id->error(scan_loc()) << "include: failed to locate file" << endl;
			const char **tried = includeChecks;
			while ( *tried != 0 )
				id->error(scan_loc()) << "include: attempted: \"" << *tried++ << '\"' << endl;
		}
		else {
			/* Don't include anything that's already been included. */
			if ( !parser->pd->duplicateInclude( includeChecks[found], inclSectionName ) ) {
				parser->pd->includeHistory.push_back( IncludeHistoryItem( 
						includeChecks[found], inclSectionName ) );

				Scanner scanner( id, includeChecks[found], *inFile, parser,
						inclSectionName, includeDepth+1, false );
				scanner.do_scan( );
			}

			delete inFile;
		}
	}
}

void Scanner::handleImport()
{
	if ( sectionPass )
		return;

	if ( active() ) {
		long length = 0;
		bool caseInsensitive = false;
		char *data = prepareLitString( id, InputLoc(), lit, lit_len, length, caseInsensitive );

		const char **importChecks = parser->pd->id->makeIncludePathChecks( fileName, data );

		/* Open the input file for reading. */
		long found = 0;
		ifstream *inFile = parser->pd->id->tryOpenInclude( importChecks, found );
		if ( inFile == 0 ) {
			id->error(scan_loc()) << "import: could not open import file " <<
					"for reading" << endl;
			const char **tried = importChecks;
			while ( *tried != 0 )
				id->error(scan_loc()) << "import: attempted: \"" << *tried++ << '\"' << endl;
		}

		Scanner scanner( id, importChecks[found], *inFile, parser,
				0, includeDepth+1, true );
		scanner.do_scan( );
		scanner.importToken( 0, 0, 0 );
		scanner.flushImport();
		delete inFile;
	}
}

%%{
	machine section_parse;

	# Need the defines representing tokens.
	import "rlparse.h"; 

	action clear_words { word = lit = 0; word_len = lit_len = 0; }
	action store_word { word = tokdata; word_len = toklen; }
	action store_lit { lit = tokdata; lit_len = toklen; }

	action mach_err { id->error(scan_loc()) << "bad machine statement" << endl; }
	action incl_err { id->error(scan_loc()) << "bad include statement" << endl; }
	action import_err { id->error(scan_loc()) << "bad import statement" << endl; }
	action write_err { id->error(scan_loc()) << "bad write statement" << endl; }

	action handle_machine { handleMachine(); }
	action handle_include { handleInclude(); }
	action handle_import { handleImport(); }

	machine_stmt =
		( KW_Machine TK_Word @store_word ';' ) @handle_machine
		<>err mach_err <>eof mach_err;

	include_names = (
		TK_Word @store_word ( TK_Literal @store_lit )? |
		TK_Literal @store_lit
	) >clear_words;

	include_stmt =
		( KW_Include include_names ';' ) @handle_include
		<>err incl_err <>eof incl_err;

	import_stmt =
		( KW_Import TK_Literal @store_lit ';' ) @handle_import
		<>err import_err <>eof import_err;

	action write_command
	{
		if ( sectionPass ) {
			InputItem *inputItem = new InputItem;
			inputItem->type = InputItem::Write;
			inputItem->loc.fileName = fileName;
			inputItem->loc.line = line;
			inputItem->loc.col = column;
			inputItem->name = section->sectionName;
			inputItem->section = section;

			/* Track the last reference. */
			inputItem->section->lastReference = inputItem;

			id->inputItems.append( inputItem );
		}
		else {
			if ( includeDepth == 0 && active() &&
					id->machineSpec == 0 && id->machineName == 0 )
			{
				id->curItem = id->curItem->next;
				id->curItem->pd = parser->pd;
				id->curItem->parser = parser;
				id->checkLastRef( id->curItem );
			}
		}
	}

	action write_arg
	{
		if ( sectionPass ) {
		}
		else {
			if ( active() && id->machineSpec == 0 && id->machineName == 0 )
				id->curItem->writeArgs.push_back( strdup(tokdata) );
		}
	}

	action write_close
	{
		if ( sectionPass ) {
		}
		else {
			/* if ( active() && id->machineSpec == 0 && id->machineName == 0 )
			 *	id->curItem->writeArgs.append( 0 ); */
		}
	}

	write_stmt =
		( KW_Write @write_command 
		( TK_Word @write_arg )+ ';' @write_close )
		<>err write_err <>eof write_err;

	action handle_token
	{
		if ( sectionPass ) {
			deleteTokdata( tokdata );
		}
		else {
			/* Send the token off to the parser. */
			if ( active() ) {
				if ( tokdata != 0 ) {
					linkTokdata( parser, tokdata );
				}

				directToParser( parser, fileName, line, column, type, tokdata, toklen );
			}
			else {
				deleteTokdata( tokdata );
			}
		}
	}

	# Catch everything else.
	everything_else = 
		^( KW_Machine | KW_Include | KW_Import | KW_Write ) @handle_token;

	main := ( 
		machine_stmt |
		include_stmt |
		import_stmt |
		write_stmt |
		everything_else
	)*;
}%%

void Scanner::token( int type, char c )
{
	token( type, &c, &c + 1 );
}

void Scanner::token( int type )
{
	token( type, 0, 0 );
}


void Scanner::token( int type, char *start, char *end )
{
	char *tokdata = 0;
	int toklen = 0;
	if ( start != 0 ) {
		toklen = end-start;
		tokdata = newTokdata( toklen + 1 );
		memcpy( tokdata, start, toklen );
		tokdata[toklen] = 0;
	}

	processToken( type, tokdata, toklen );
}

void Scanner::processToken( int type, char *tokdata, int toklen )
{
	int *p, *pe, *eof;

	if ( type < 0 )
		p = pe = eof = 0;
	else {
		p = &type;
		pe = &type + 1;
		eof = 0;
	}

	%%{
		machine section_parse;
		write exec;
	}%%

	updateCol();

	/* Record the last token for use in controlling the scan of subsequent
	 * tokens. */
	lastToken = type;
}

void Scanner::startSection( )
{
	parserExistsError = false;

	sectionLoc.fileName = fileName;
	sectionLoc.line = line;
	sectionLoc.col = column;
}

void Scanner::endSection( )
{
	/* Execute the eof actions for the section parser. */
	processToken( -1, 0, 0 );

	if ( sectionPass ) {
		InputItem *inputItem = new InputItem;
		inputItem->type = InputItem::EndSection;
		inputItem->loc.fileName = fileName;
		inputItem->loc.line = line;
		inputItem->loc.col = column;
		id->inputItems.append( inputItem );
		if ( section != 0 ) {
			inputItem->section = section;
			section->lastReference = inputItem;
		}

		if ( includeDepth == 0 ) {
			if ( id->machineSpec == 0 && id->machineName == 0 ) {
				/* The end section may include a newline on the end, so
				 * we use the last line, which will count the newline. */
				InputItem *inputItem = new InputItem;
				inputItem->type = InputItem::HostData;
				inputItem->loc.fileName = fileName;
				inputItem->loc.line = line;
				inputItem->loc.col = column;
				id->inputItems.append( inputItem );
			}
		}
	}
	else {
		/* Close off the section with the parser. */
		if ( includeDepth == 0 && active() ) {
			InputLoc loc;
			loc.fileName = fileName;
			loc.line = line;
			loc.col = column;

			parser->token( loc, TK_EndSection, 0, 0 );

			id->curItem = id->curItem->next;

			if ( parser != 0 ) {
				id->curItem->pd = parser->pd;
				id->curItem->parser = parser;
			}

			id->checkLastRef( id->curItem );
		}

		if ( includeDepth == 0 ) {
			if ( id->machineSpec == 0 && id->machineName == 0 ) {
				id->curItem = id->curItem->next;
				id->checkLastRef( id->curItem );
			}
		}
	}
}

%%{
	machine rlscan;

	# This is sent by the driver code.
	EOF = 0;
	
	action inc_nl { 
		lastnl = p; 
		column = 0;
		line++;
	}
	NL = '\n' @inc_nl;

	# Identifiers, numbers, commetns, and other common things.
	ident = ( alpha | '_' ) ( alpha |digit |'_' )*;
	ocaml_ident = ( alpha | '_' ) ( alpha |digit |'_' )* "'"?;
	number = digit+;
	hex_number = '0x' [0-9a-fA-F]+;

	c_comment = 
		'/*' ( any | NL )* :>> '*/';

	cpp_comment =
		'//' [^\n]* NL;

	c_cpp_comment = c_comment | cpp_comment;

	ruby_comment = '#' [^\n]* NL;

	# These literal forms are common to host code and ragel.
	s_literal = "'" ([^'\\] | NL | '\\' (any | NL))* "'";
	d_literal = '"' ([^"\\] | NL | '\\' (any | NL))* '"';
	host_re_literal = '/' ([^/\\] | NL | '\\' (any | NL))* '/';

	whitespace = [ \t] | NL;
	pound_comment = '#' [^\n]* NL;

	# An inline block of code for languages other than Ruby.
	inline_code := |*
		# Inline expression keywords.
		"fpc" => { token( KW_PChar ); };
		"fc" => { token( KW_Char ); };
		"fcurs" => { token( KW_CurState ); };
		"ftargs" => { token( KW_TargState ); };
		"fentry" => { 
			whitespaceOn = false; 
			token( KW_Entry );
		};

		# Inline statement keywords.
		"fhold" => { 
			whitespaceOn = false; 
			token( KW_Hold );
		};
		"fexec" => { token( KW_Exec, 0, 0 ); };
		"fgoto" => { 
			whitespaceOn = false; 
			token( KW_Goto );
		};
		"fnext" => { 
			whitespaceOn = false; 
			token( KW_Next );
		};
		"fcall" => { 
			whitespaceOn = false; 
			token( KW_Call );
		};
		"fret" => { 
			whitespaceOn = false; 
			token( KW_Ret );
		};
		"fbreak" => { 
			whitespaceOn = false; 
			token( KW_Break );
		};
		"fncall" => { 
			whitespaceOn = false; 
			token( KW_Ncall );
		};
		"fnret" => { 
			whitespaceOn = false; 
			token( KW_Nret );
		};
		"fnbreak" => { 
			whitespaceOn = false; 
			token( KW_Nbreak );
		};

		ident => { token( TK_Word, ts, te ); };

		number => { token( TK_UInt, ts, te ); };
		hex_number => { token( TK_Hex, ts, te ); };

		( s_literal | d_literal ) 
			=> { token( IL_Literal, ts, te ); };

		whitespace+ => { 
			if ( whitespaceOn ) 
				token( IL_WhiteSpace, ts, te );
		};

		c_cpp_comment => { token( IL_Comment, ts, te ); };

		"::" => { token( TK_NameSep, ts, te ); };

		# Some symbols need to go to the parser as with their cardinal value as
		# the token type (as opposed to being sent as anonymous symbols)
		# because they are part of the sequences which we interpret. The * ) ;
		# symbols cause whitespace parsing to come back on. This gets turned
		# off by some keywords.

		";" => {
			whitespaceOn = true;
			token( *ts, ts, te );
			if ( inlineBlockType == SemiTerminated )
				fret;
		};

		"$" [a-zA-Z_][a-zA-Z_0-9]* => {
			if ( parser != 0 && parser->parseSubstitutions )
				token( TK_SubstRef, ts+1, te );
			else {
				token( IL_Symbol, ts, ts+1 );
				fexec ts+1;
			}
		};

		[*)] => { 
			whitespaceOn = true;
			token( *ts, ts, te );
		};

		[,(] => { token( *ts, ts, te ); };

		'{' => { 
			token( IL_Symbol, ts, te );
			curly_count += 1; 
		};

		'}' => { 
			if ( --curly_count == 0 && inlineBlockType == CurlyDelimited ) {
				/* Inline code block ends. */
				token( '}' );
				fret;
			}
			else {
				/* Either a semi terminated inline block or only the closing
				 * brace of some inner scope, not the block's closing brace. */
				token( IL_Symbol, ts, te );
			}
		};

		EOF => {
			id->error(scan_loc()) << "unterminated code block" << endl;
		};

		# Send every other character as a symbol.
		any => { token( IL_Symbol, ts, te ); };
	*|;

	or_literal := |*
		# Escape sequences in OR expressions.
		'\\0' => { token( RE_Char, '\0' ); };
		'\\a' => { token( RE_Char, '\a' ); };
		'\\b' => { token( RE_Char, '\b' ); };
		'\\t' => { token( RE_Char, '\t' ); };
		'\\n' => { token( RE_Char, '\n' ); };
		'\\v' => { token( RE_Char, '\v' ); };
		'\\f' => { token( RE_Char, '\f' ); };
		'\\r' => { token( RE_Char, '\r' ); };
		'\\\n' => { updateCol(); };
		'\\' any => { token( RE_Char, ts+1, te ); };

		# Range dash in an OR expression.
		'-' => { token( RE_Dash, 0, 0 ); };

		# Terminate an OR expression.
		']'	=> { token( RE_SqClose ); fret; };

		EOF => {
			id->error(scan_loc()) << "unterminated OR literal" << endl;
		};

		# Characters in an OR expression.
		[^\]] => { token( RE_Char, ts, te ); };

	*|;

	ragel_re_literal := |*
		# Escape sequences in regular expressions.
		'\\0' => { token( RE_Char, '\0' ); };
		'\\a' => { token( RE_Char, '\a' ); };
		'\\b' => { token( RE_Char, '\b' ); };
		'\\t' => { token( RE_Char, '\t' ); };
		'\\n' => { token( RE_Char, '\n' ); };
		'\\v' => { token( RE_Char, '\v' ); };
		'\\f' => { token( RE_Char, '\f' ); };
		'\\r' => { token( RE_Char, '\r' ); };
		'\\\n' => { updateCol(); };
		'\\' any => { token( RE_Char, ts+1, te ); };

		# Terminate an OR expression.
		'/' [i]? => { 
			token( RE_Slash, ts, te ); 
			fgoto parser_def;
		};

		# Special characters.
		'.' => { token( RE_Dot ); };
		'*' => { token( RE_Star ); };

		'[' => { token( RE_SqOpen ); fcall or_literal; };
		'[^' => { token( RE_SqOpenNeg ); fcall or_literal; };

		EOF => {
			id->error(scan_loc()) << "unterminated regular expression" << endl;
		};

		# Characters in an OR expression.
		[^\/] => { token( RE_Char, ts, te ); };
	*|;

	# We need a separate token space here to avoid the ragel keywords.
	write_statement := |*
		ident => { token( TK_Word, ts, te ); } ;
		[ \t\n]+ => { updateCol(); };
		';' => { token( ';' ); fgoto parser_def; };

		EOF => {
			id->error(scan_loc()) << "unterminated write statement" << endl;
		};
	*|;

	# Parser definitions. 
	parser_def := |*
		#'length_cond' => { token( KW_Length ); };
		'machine' => { token( KW_Machine ); };
		'include' => { token( KW_Include ); };
		'import' => { token( KW_Import ); };
		'write' => { 
			token( KW_Write );
			fgoto write_statement;
		};
		'action' => { token( KW_Action ); };
		'alphtype' => { token( KW_AlphType ); };
		'prepush' => { token( KW_PrePush ); };
		'postpop' => { token( KW_PostPop ); };

		'nfaprepush' => { token( KW_NfaPrePush ); };
		'nfapostpop' => { token( KW_NfaPostPop ); };

		# FIXME: Enable this post 5.17.
		# 'range' => { token( KW_Range ); };

		'getkey' => { 
			token( KW_GetKey );
			inlineBlockType = SemiTerminated;
			fcall inline_code;
		};
		'access' => { 
			token( KW_Access );
			inlineBlockType = SemiTerminated;
			fcall inline_code;
		};
		'variable' => { 
			token( KW_Variable );
			inlineBlockType = SemiTerminated;
			fcall inline_code;
		};
		'when' => { token( KW_When ); };
		'inwhen' => { token( KW_InWhen ); };
		'outwhen' => { token( KW_OutWhen ); };
		'eof' => { token( KW_Eof ); };
		'err' => { token( KW_Err ); };
		'lerr' => { token( KW_Lerr ); };
		'to' => { token( KW_To ); };
		'from' => { token( KW_From ); };
		'export' => { token( KW_Export ); };

		# Identifiers.
		ident => { token( TK_Word, ts, te ); } ;

		# Numbers
		number => { token( TK_UInt, ts, te ); };
		hex_number => { token( TK_Hex, ts, te ); };

		# Literals, with optionals.
		( s_literal | d_literal ) [i]? 
			=> { token( TK_Literal, ts, te ); };

		'[' => { token( RE_SqOpen ); fcall or_literal; };
		'[^' => { token( RE_SqOpenNeg ); fcall or_literal; };

		'/' => { token( RE_Slash ); fgoto ragel_re_literal; };

		# Ignore.
		pound_comment => { updateCol(); };

		':=' => { token( TK_ColonEquals ); };
		'|=' => { token( TK_BarEquals ); };

		# To State Actions.
		">~" => { token( TK_StartToState ); };
		"$~" => { token( TK_AllToState ); };
		"%~" => { token( TK_FinalToState ); };
		"<~" => { token( TK_NotStartToState ); };
		"@~" => { token( TK_NotFinalToState ); };
		"<>~" => { token( TK_MiddleToState ); };

		# From State actions
		">*" => { token( TK_StartFromState ); };
		"$*" => { token( TK_AllFromState ); };
		"%*" => { token( TK_FinalFromState ); };
		"<*" => { token( TK_NotStartFromState ); };
		"@*" => { token( TK_NotFinalFromState ); };
		"<>*" => { token( TK_MiddleFromState ); };

		# EOF Actions.
		">/" => { token( TK_StartEOF ); };
		"$/" => { token( TK_AllEOF ); };
		"%/" => { token( TK_FinalEOF ); };
		"</" => { token( TK_NotStartEOF ); };
		"@/" => { token( TK_NotFinalEOF ); };
		"<>/" => { token( TK_MiddleEOF ); };

		# Global Error actions.
		">!" => { token( TK_StartGblError ); };
		"$!" => { token( TK_AllGblError ); };
		"%!" => { token( TK_FinalGblError ); };
		"<!" => { token( TK_NotStartGblError ); };
		"@!" => { token( TK_NotFinalGblError ); };
		"<>!" => { token( TK_MiddleGblError ); };

		# Local error actions.
		">^" => { token( TK_StartLocalError ); };
		"$^" => { token( TK_AllLocalError ); };
		"%^" => { token( TK_FinalLocalError ); };
		"<^" => { token( TK_NotStartLocalError ); };
		"@^" => { token( TK_NotFinalLocalError ); };
		"<>^" => { token( TK_MiddleLocalError ); };

		# Middle.
		"<>" => { token( TK_Middle ); };

		# Conditions. 
		'>?' => { token( TK_StartCond ); };
		'$?' => { token( TK_AllCond ); };
		'%?' => { token( TK_LeavingCond ); };

		'..'   => { token( TK_DotDot ); };
		'../i' => { token( TK_DotDotIndep ); };

		'**' => { token( TK_StarStar ); };
		'--' => { token( TK_DashDash ); };
		'->' => { token( TK_Arrow ); };
		'=>' => { token( TK_DoubleArrow ); };

		":>"  => { token( TK_ColonGt ); };
		":>>" => { token( TK_ColonGtGt ); };
		"<:"  => { token( TK_LtColon ); };

		":nfa("   => { token( TK_ColonNfaOpen ); };
		":cond("  => { token( TK_ColonCondOpen ); };
		":condstar("  => { token( TK_ColonCondStarOpen ); };
		":condplus("  => { token( TK_ColonCondPlusOpen ); };
		":nomax(" => { token( TK_ColonNoMaxOpen ); };
		"):"      => { token( TK_CloseColon ); };

		# Opening of longest match.
		"|*" => { token( TK_BarStar ); };

		# Separater for name references.
		"::" => { token( TK_NameSep, ts, te ); };

		'}%%' => { 
			updateCol();
			endSection();
			fret;
		};

		[ \t\r]+ => { updateCol(); };

		# If we are in a single line machine then newline may end the spec.
		NL => {
			updateCol();
			if ( singleLineSpec ) {
				endSection();
				fret;
			}
		};

		'{' => { 
			if ( lastToken == KW_Export || lastToken == KW_Entry )
				token( '{' );
			else {
				token( '{' );
				curly_count = 1; 
				inlineBlockType = CurlyDelimited;
				fcall inline_code;
			}
		};

		EOF => {
			id->error(scan_loc()) << "unterminated ragel section" << endl;
		};

		any => { token( *ts ); } ;
	*|;

	# Outside code scanner. These tokens get passed through.
	main := |*
		'define' => { pass( IMP_Define, 0, 0 ); };
		ident => { pass( IMP_Word, ts, te ); };
		number => { pass( IMP_UInt, ts, te ); };
		c_cpp_comment => { pass(); };
		( s_literal | d_literal ) => { pass( IMP_Literal, ts, te ); };

		'%%{' => { 
			updateCol();
			singleLineSpec = false;
			startSection();
			fcall parser_def;
		};
		'%%' => { 
			updateCol();
			singleLineSpec = true;
			startSection();
			fcall parser_def;
		};
		whitespace+ => { pass(); };
		EOF;
		any => { pass( *ts, 0, 0 ); };
	*|;
}%%

%% write data;

void Scanner::do_scan()
{
	int bufsize = 8;
	char *buf = new char[bufsize];
	int cs, act, have = 0;
	int top;

	/* The stack is two deep, one level for going into ragel defs from the main
	 * machines which process outside code, and another for going into or literals
	 * from either a ragel spec, or a regular expression. */
	int stack[2];
	int curly_count = 0;
	bool execute = true;
	bool singleLineSpec = false;
	InlineBlockType inlineBlockType = CurlyDelimited;

	line = 1;
	column = 1;
	lastnl = 0;

	/* Init the section parser and the character scanner. */
	init();
	%% write init;

	/* Set up the start state. FIXME: After 5.20 is released the nocs write
	 * init option should be used, the main machine eliminated and this statement moved
	 * above the write init. */
	cs = rlscan_en_main;
	
	while ( execute ) {
		char *p = buf + have;
		int space = bufsize - have;

		if ( space == 0 ) {
			/* We filled up the buffer trying to scan a token. Grow it. */
			bufsize = bufsize * 2;
			char *newbuf = new char[bufsize];

			/* Recompute p and space. */
			p = newbuf + have;
			space = bufsize - have;

			/* Patch up pointers possibly in use. */
			if ( ts != 0 )
				ts = newbuf + ( ts - buf );
			te = newbuf + ( te - buf );

			/* Copy the new buffer in. */
			memcpy( newbuf, buf, have );
			delete[] buf;
			buf = newbuf;
		}

		input.read( p, space );
		int len = input.gcount();
		char *pe = p + len;

		/* If we see eof then append the eof var. */
		char *eof = 0;
	 	if ( len == 0 ) {
			eof = pe;
			execute = false;
		}

		%% write exec;

		/* Check if we failed. */
		if ( cs == rlscan_error ) {
			/* Machine failed before finding a token. I'm not yet sure if this
			 * is reachable. */
			id->error(scan_loc()) << "scanner error" << endl;
			id->abortCompile( 1 );
		}

		/* Decide if we need to preserve anything. */
		char *preserve = ts;

		/* Now set up the prefix. */
		if ( preserve == 0 )
			have = 0;
		else {
			/* There is data that needs to be shifted over. */
			have = pe - preserve;
			memmove( buf, preserve, have );
			unsigned int shiftback = preserve - buf;
			if ( ts != 0 )
				ts -= shiftback;
			te -= shiftback;

			preserve = buf;
		}
	}

	delete[] buf;
}
