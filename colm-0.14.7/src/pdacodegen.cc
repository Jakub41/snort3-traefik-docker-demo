/*
 * Copyright 2006-2018 Adrian Thurston <thurston@colm.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>

#include <iostream>
#include <iomanip>

#include "compiler.h"
#include "pdacodegen.h"

using std::cerr;
using std::endl;

#define FRESH_BLOCK 8128
#define act_sb "0x1"
#define act_rb "0x2"
#define lower "0x0000ffff"
#define upper "0xffff0000"

void escapeLiteralString( std::ostream &out, const char *path, int length )
{
	for ( const char *pc = path, *end = path+length; pc != end; pc++ ) {
		switch ( *pc ) {
			case '\\': out << "\\\\"; break;
			case '"':  out << "\\\""; break;
			case '\a': out << "\\a"; break;
			case '\b': out << "\\b"; break;
			case '\t': out << "\\t"; break;
			case '\n': out << "\\n"; break;
			case '\v': out << "\\v"; break;
			case '\f': out << "\\f"; break;
			case '\r': out << "\\r"; break;
			default:   out << *pc; break;
		}
	}
}

void escapeLiteralString( std::ostream &out, const char *path )
{
	escapeLiteralString( out, path, strlen(path) );
}

void PdaCodeGen::defineRuntime()
{
	out << 
		"extern struct colm_sections " << objectName << ";\n"
		"\n";
}

void PdaCodeGen::writeRuntimeData( colm_sections *runtimeData, struct pda_tables *pdaTables )
{
	/*
	 * Blocks of code in frames.
	 */
	for ( int i = 0; i < runtimeData->num_frames; i++ ) {
		/* FIXME: horrible code cloning going on here. */
		if ( runtimeData->frame_info[i].codeLenWV > 0 ) {
			out << "static code_t code_" << i << "_wv[] = {\n\t";

			code_t *block = runtimeData->frame_info[i].codeWV;
			for ( int j = 0; j < runtimeData->frame_info[i].codeLenWV; j++ ) {
				out << (unsigned long) block[j];

				if ( j < runtimeData->frame_info[i].codeLenWV-1 ) {
					out << ", ";
					if ( (j+1) % 8 == 0 )
						out << "\n\t";
				}
			}
			out << "\n};\n\n";
		}

		if ( runtimeData->frame_info[i].codeLenWC > 0 ) {
			out << "static code_t code_" << i << "_wc[] = {\n\t";

			code_t *block = runtimeData->frame_info[i].codeWC;
			for ( int j = 0; j < runtimeData->frame_info[i].codeLenWC; j++ ) {
				out << (unsigned long) block[j];

				if ( j < runtimeData->frame_info[i].codeLenWC-1 ) {
					out << ", ";
					if ( (j+1) % 8 == 0 )
						out << "\n\t";
				}
			}
			out << "\n};\n\n";
		}

		if ( runtimeData->frame_info[i].locals_len > 0 ) {
			out << "static struct local_info locals_" << i << "[] = {\n\t";

			struct local_info *li = runtimeData->frame_info[i].locals;
			for ( int j = 0; j < runtimeData->frame_info[i].locals_len; j++ ) {
				out << "{ " << (int)li[j].type << ", " << li[j].offset << " }";

				if ( j < runtimeData->frame_info[i].locals_len-1 ) {
					out << ", ";
					if ( (j+1) % 8 == 0 )
						out << "\n\t";
				}
			}
			out << "\n};\n\n";
		}
	}

	/*
	 * Blocks in production info.
	 */
	for ( int i = 0; i < runtimeData->num_prods; i++ ) {
		if ( runtimeData->prod_info[i].copy_len > 0 ) {
			out << "static unsigned char copy_" << i << "[] = {\n\t";

			unsigned char *block = runtimeData->prod_info[i].copy;
			for ( int j = 0; j < runtimeData->prod_info[i].copy_len; j++ ) {
				out << (long) block[j*2] << ", " << (long) block[j*2+1];

				if ( j < runtimeData->prod_info[i].copy_len-1 ) {
					out << ", ";
					if ( (j+1) % 8 == 0 )
						out << "\n\t";
				}
			}
			out << "\n};\n\n";
		}
	}

	/* 
	 * Init code.
	 */
	out << "static code_t " << rootCode() << "[] = {\n\t";
	code_t *block = runtimeData->root_code ;
	for ( int j = 0; j < runtimeData->root_code_len; j++ ) {
		out << (unsigned int) block[j];

		if ( j < runtimeData->root_code_len-1 ) {
			out << ", ";
			if ( (j+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	/*
	 * lelInfo
	 */
	out << "static struct lang_el_info " << lelInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_lang_els; i++ ) {
		struct lang_el_info *el = &runtimeData->lel_info[i];
		out << "/* " << std::setw(4) << i << " */ {";
		
		/* Name. */
		out << " \"";
		escapeLiteralString( out, el->name );
		out << "\", ";

		/* Name. */
		out << " \"";
		escapeLiteralString( out, el->xml_tag );
		out << "\", ";
		
		/* Repeat, literal, ignore flags. */
		out << (int)el->repeat << ", ";
		out << (int)el->list << ", ";
		out << (int)el->literal << ", ";
		out << (int)el->ignore << ", ";
		out << el->frame_id << ", ";
		out << el->object_type_id << ", ";
		out << el->ofi_offset << ", ";
		out << el->object_length << ", ";
		out << el->term_dup_id << ", ";
		out << el->mark_id << ", ";
		out << el->capture_attr << ", ";
		out << el->num_capture_attr;

		out << " }";

		if ( i < runtimeData->num_lang_els-1 )
			out << ",\n";
	}
	out << "\n};\n\n";


	for ( int i = 0; i < runtimeData->num_struct_els; i++ ) {
		struct struct_el_info *el = &runtimeData->sel_info[i];
		if ( el->trees_len > 0 ) {
			out << "static short struct_trees_" << i << "[] = {\n\t";

			short *ti = el->trees;
			for ( int j = 0; j < el->trees_len; j++ )
				out << ti[j] << ", ";
			out << "\n};\n\n";
		}
	}

	/*
	 * selInfo
	 */
	out << "static struct struct_el_info " << selInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_struct_els; i++ ) {
		struct struct_el_info *el = &runtimeData->sel_info[i];
		out << "\t{ ";
		out << el->size << ", ";

		/* trees. */
		if ( el->trees_len > 0 )
			out << "struct_trees_" << i << ", ";
		else
			out << "0, ";
		out << el->trees_len << ", ";

		out << " },\n";
	}
	out << "\n};\n\n";

	/*
	 * frameInfo
	 */
	out << "static struct frame_info " << frameInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_frames; i++ ) {
		out << "\t{ ";

		/* The Name. */
		if ( runtimeData->frame_info[i].name )
			out << "\"" << runtimeData->frame_info[i].name << "\", ";
		else 
			out << "\"\", ";

		if ( runtimeData->frame_info[i].codeLenWV > 0 )
			out << "code_" << i << "_wv, ";
		else
			out << "0, ";
		out << runtimeData->frame_info[i].codeLenWV << ", ";

		if ( runtimeData->frame_info[i].codeLenWC > 0 )
			out << "code_" << i << "_wc, ";
		else
			out << "0, ";
		out << runtimeData->frame_info[i].codeLenWC << ", ";

		/* locals. */
		if ( runtimeData->frame_info[i].locals_len > 0 )
			out << "locals_" << i << ", ";
		else
			out << "0, ";

		out << runtimeData->frame_info[i].locals_len << ", ";

		out <<
			runtimeData->frame_info[i].arg_size << ", " <<
			runtimeData->frame_info[i].frame_size;

		out << " }";

		if ( i < runtimeData->num_frames-1 )
			out << ",\n";
	}
	out << "\n};\n\n";


	/*
	 * prodInfo
	 */
	out << "static struct prod_info " << prodInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_prods; i++ ) {
		out << "\t{ ";

		out << runtimeData->prod_info[i].lhs_id << ", ";
		out << runtimeData->prod_info[i].prod_num << ", ";
		out << runtimeData->prod_info[i].length << ", ";

		out <<
			'"' << runtimeData->prod_info[i].name << "\", " << 
			runtimeData->prod_info[i].frame_id << ", " << 
			(int)runtimeData->prod_info[i].lhs_upref << ", ";

		if ( runtimeData->prod_info[i].copy_len > 0 )
			out << "copy_" << i << ", ";
		else
			out << "0, ";

		out << runtimeData->prod_info[i].copy_len << ", ";


		out << " }";

		if ( i < runtimeData->num_prods-1 )
			out << ",\n";
	}
	out << "\n};\n\n";

	/*
	 * patReplInfo
	 */
	out << "static struct pat_cons_info " << patReplInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_patterns; i++ ) {
		out << "	{ " << runtimeData->pat_repl_info[i].offset << ", " <<
				runtimeData->pat_repl_info[i].num_bindings << " },\n";
	}
	out << "};\n\n";

	/*
	 * patReplNodes
	 */
	out << "static struct pat_cons_node " << patReplNodes() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_pattern_nodes; i++ ) {
		struct pat_cons_node &node = runtimeData->pat_repl_nodes[i];
		out << "	{ " << node.id << ", " << 
				node.prod_num << ", " << node.next << ", " << 
				node.child << ", " << node.bind_id << ", ";
		if ( node.data == 0 )
			out << "0";
		else {
			out << '\"';
			escapeLiteralString( out, node.data, node.length );
			out << '\"';
		}
		out << ", " << node.length << ", ";

		out << node.left_ignore << ", ";
		out << node.right_ignore << ", ";

		out << (int)node.stop << " },\n";
	}
	out << "};\n\n";

	/*
	 * functionInfo
	 */
	out << "static struct function_info " << functionInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_functions; i++ ) {
		out << "\t{ " <<
				runtimeData->function_info[i].frame_id << ", " <<
				runtimeData->function_info[i].arg_size << ", " <<
				runtimeData->function_info[i].frame_size;
		out << " }";

		if ( i < runtimeData->num_functions-1 )
			out << ",\n";
	}
	out << "\n};\n\n";

	/*
	 * regionInfo
	 */
	out << "static struct region_info " << regionInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_regions; i++ ) {
		out << "\t{ " << runtimeData->region_info[i].default_token <<
			", " << runtimeData->region_info[i].eof_frame_id <<
			", " << runtimeData->region_info[i].ci_lel_id <<
			" }";

		if ( i < runtimeData->num_regions-1 )
			out << ",\n";
	}
	out << "\n};\n\n";

	/* 
	 * genericInfo
	 */
	out << "static struct generic_info " << genericInfo() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_generics; i++ ) {
		out << "\t{ " << 
				runtimeData->generic_info[i].type << ", " <<
				runtimeData->generic_info[i].el_struct_id << ", " <<
				runtimeData->generic_info[i].el_offset << ", " <<
				runtimeData->generic_info[i].key_type << ", " <<
				runtimeData->generic_info[i].key_offset << ", " <<
				runtimeData->generic_info[i].value_type << ", " <<
				runtimeData->generic_info[i].value_offset << ", " <<
				runtimeData->generic_info[i].parser_id;
		out << " },\n";
	}
	out << "};\n\n";

	/* 
	 * literals
	 */
	out << "static const char *" << litdata() << "[] = {\n";
	for ( int i = 0; i < runtimeData->num_literals; i++ ) {
		out << "\t\"";
		escapeLiteralString( out, runtimeData->litdata[i], runtimeData->litlen[i] );
		out << "\",\n";
	}
	out << "};\n\n";

	out << "static long " << litlen() << "[] = {\n\t";
	for ( int i = 0; i < runtimeData->num_literals; i++ )
		out << runtimeData->litlen[i] << ", ";
	out << "};\n\n";

	out << "static head_t *" << literals() << "[] = {\n\t";
	for ( int i = 0; i < runtimeData->num_literals; i++ )
		out << "0, ";
	out << "};\n\n";

	out << "static int startStates[] = {\n\t";
	for ( long i = 0; i < runtimeData->num_parsers; i++ ) {
		out << runtimeData->start_states[i] << ", ";
	}
	out << "};\n\n";

	out << "static int eofLelIds[] = {\n\t";
	for ( long i = 0; i < runtimeData->num_parsers; i++ ) {
		out << runtimeData->eof_lel_ids[i] << ", ";
	}
	out << "};\n\n";

	out << "static int parserLelIds[] = {\n\t";
	for ( long i = 0; i < runtimeData->num_parsers; i++ ) {
		out << runtimeData->parser_lel_ids[i] << ", ";
	}
	out << "};\n\n";

	out << "static CaptureAttr captureAttr[] = {\n";
	for ( long i = 0; i < runtimeData->num_captured_attr; i++ ) {
		out << "\t{ " << 
			runtimeData->capture_attr[i].mark_enter << ", " <<
			runtimeData->capture_attr[i].mark_leave << ", " <<
			runtimeData->capture_attr[i].offset  << " },\n";
	}

	out << "};\n\n";

	out <<
		"tree_t **" << objectName << "_host_call( program_t *prg, long code, tree_t **sp );\n"
		"void " << objectName << "_commit_reduce_forward( program_t *prg, tree_t **root,\n"
		"		struct pda_run *pda_run, parse_tree_t *pt );\n"
		"long " << objectName << "_commit_union_sz( int reducer );\n"
		"void " << objectName << "_init_need();\n"
		"int " << objectName << "_reducer_need_tok( program_t *prg, "
				"struct pda_run *pda_run, int id );\n"
		"int " << objectName << "_reducer_need_ign( program_t *prg, "
				"struct pda_run *pda_run );\n"
		"void " << objectName << "_read_reduce( program_t *prg, int reducer, input_t *stream );\n"
		"\n";

	out <<
		"static struct export_info " << exportInfo() << "[] = {\n";

	for ( long i = 0; i < runtimeData->num_exports; i++ ) {
		out << "	{ \"" << runtimeData->export_info[i].name << "\", " <<
				runtimeData->export_info[i].global_id << " },\n";
	}

	out <<
		"};\n";

	for ( long i = 0; i < runtimeData->num_exports; i++ ) {
		out << "const int colm_export_" << runtimeData->export_info[i].name << " = " <<
				runtimeData->export_info[i].global_id << ";\n";
	}
	out <<
		"\n";

	out <<
		"struct colm_sections " << objectName << " = \n"
		"{\n"
		"	" << lelInfo() << ",\n"
		"	" << runtimeData->num_lang_els << ",\n"
		"\n"
		"	" << selInfo() << ",\n"
		"	" << runtimeData->num_struct_els << ",\n"
		"\n"
		"	" << prodInfo() << ",\n"
		"	" << runtimeData->num_prods << ",\n"
		"\n"
		"	" << regionInfo() << ",\n"
		"	" << runtimeData->num_regions << ",\n"
		"\n"
		"	" << rootCode() << ",\n"
		"	" << runtimeData->root_code_len << ",\n"
		"	" << runtimeData->root_frame_id << ",\n"
		"\n"
		"	" << frameInfo() << ",\n"
		"	" << runtimeData->num_frames << ",\n"
		"\n"
		"	" << functionInfo() << ",\n"
		"	" << runtimeData->num_functions << ",\n"
		"\n"
		"	" << patReplInfo() << ",\n"
		"	" << runtimeData->num_patterns << ",\n"
		"\n"
		"	" << patReplNodes() << ",\n"
		"	" << runtimeData->num_pattern_nodes << ",\n"
		"\n"
		"	" << genericInfo() << ",\n"
		"	" << runtimeData->num_generics << ",\n"
		"\n"
		"	" << exportInfo() << ",\n"
		"	" << runtimeData->num_exports << ",\n"
		"\n"
		"	" << runtimeData->argv_generic_id << ",\n"
		"	" << runtimeData->stds_generic_id << ",\n"
		"\n"
		"	" << litdata() << ",\n"
		"	" << litlen() << ",\n"
		"	" << literals() << ",\n"
		"	" << runtimeData->num_literals << ",\n"
		"\n"
		"	captureAttr,\n"
		"	" << runtimeData->num_captured_attr << ",\n"
		"\n"
		"	&fsmTables_start,\n"
		"	&pid_0_pdaTables,\n"
		"	startStates, eofLelIds, parserLelIds, " << runtimeData->num_parsers << ",\n"
		"\n"
		"	" << runtimeData->global_size << ",\n"
		"\n"
		"	" << runtimeData->first_non_term_id << ",\n"
		"	" << runtimeData->first_struct_el_id << ",\n"
		"	" << runtimeData->integer_id << ",\n"
		"	" << runtimeData->string_id << ",\n"
		"	" << runtimeData->any_id << ",\n"
		"	" << runtimeData->eof_id << ",\n"
		"	" << runtimeData->no_token_id << ",\n"
		"	" << runtimeData->global_id << ",\n"
		"	" << runtimeData->argv_el_id << ",\n"
		"	" << runtimeData->stds_el_id << ",\n"
		"	" << runtimeData->struct_inbuilt_id << ",\n"
		"	" << runtimeData->struct_inbuilt_id << ",\n"
		"	" << runtimeData->struct_stream_id << ",\n"
		"	&fsm_execute,\n"
		"	&sendNamedLangEl,\n"
		"	&initBindings,\n"
		"	&popBinding,\n"
		"	&" << objectName << "_host_call,\n"
		"	&" << objectName << "_commit_reduce_forward,\n" 
		"	&" << objectName << "_commit_union_sz,\n"
		"	&" << objectName << "_init_need,\n"
		"	&" << objectName << "_reducer_need_tok,\n"
		"	&" << objectName << "_reducer_need_ign,\n"
		"	&" << objectName << "_read_reduce,\n" 
		"};\n"
		"\n";
}

void PdaCodeGen::writeParserData( long id, struct pda_tables *tables )
{
	String prefix = "pid_" + String(0, "%ld", id) + "_";

	out << "static int " << prefix << indices() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_indices; i++ ) {
		out << tables->indices[i];

		if ( i < tables->num_indices-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static int " << prefix << owners() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_indices; i++ ) {
		out << tables->owners[i];

		if ( i < tables->num_indices-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static int " << prefix << keys() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_keys; i++ ) {
		out << tables->keys[i];

		if ( i < tables->num_keys-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static unsigned int " << prefix << offsets() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_states; i++ ) {
		out << tables->offsets[i];

		if ( i < tables->num_states-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static unsigned int " << prefix << targs() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_targs; i++ ) {
		out << tables->targs[i];

		if ( i < tables->num_targs-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static unsigned int " << prefix << actInds() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_act_inds; i++ ) {
		out << tables->act_inds[i];

		if ( i < tables->num_act_inds-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static unsigned int " << prefix << actions() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_actions; i++ ) {
		out << tables->actions[i];

		if ( i < tables->num_actions-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static int " << prefix << commitLen() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_commit_len; i++ ) {
		out << tables->commit_len[i];

		if ( i < tables->num_commit_len-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static int " << prefix << tokenRegionInds() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_states; i++ ) {
		out << tables->token_region_inds[i];

		if ( i < tables->num_states-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static int " << prefix << tokenRegions() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_region_items; i++ ) {
		out << tables->token_regions[i];

		if ( i < tables->num_region_items-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << "static int " << prefix << tokenPreRegions() << "[] = {\n\t";
	for ( int i = 0; i < tables->num_pre_region_items; i++ ) {
		out << tables->token_pre_regions[i];

		if ( i < tables->num_pre_region_items-1 ) {
			out << ", ";
			if ( (i+1) % 8 == 0 )
				out << "\n\t";
		}
	}
	out << "\n};\n\n";

	out << 
		"static struct pda_tables " << prefix << "pdaTables =\n"
		"{\n"
		"	" << prefix << indices() << ",\n"
		"	" << prefix << owners() << ",\n"
		"	" << prefix << keys() << ",\n"
		"	" << prefix << offsets() << ",\n"
		"	" << prefix << targs() << ",\n"
		"	" << prefix << actInds() << ",\n"
		"	" << prefix << actions() << ",\n"
		"	" << prefix << commitLen() << ",\n"

		"	" << prefix << tokenRegionInds() << ",\n"
		"	" << prefix << tokenRegions() << ",\n"
		"	" << prefix << tokenPreRegions() << ",\n"
		"\n"
		"	" << tables->num_indices << ",\n"
		"	" << tables->num_keys << ",\n"
		"	" << tables->num_states << ",\n"
		"	" << tables->num_targs << ",\n"
		"	" << tables->num_act_inds << ",\n"
		"	" << tables->num_actions << ",\n"
		"	" << tables->num_commit_len << ",\n"
		"	" << tables->num_region_items << ",\n"
		"	" << tables->num_pre_region_items << "\n"
		"};\n"
		"\n";
}

