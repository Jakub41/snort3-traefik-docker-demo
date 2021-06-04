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
#include <assert.h>
#include <stdlib.h>

#include <colm/pdarun.h>
#include <colm/tree.h>
#include <colm/bytecode.h>
#include <colm/pool.h>
#include <colm/debug.h>
#include <colm/struct.h>

#define VM_STACK_SIZE (8192)

static void colm_alloc_global( program_t *prg )
{
	/* Alloc the global. */
	prg->global = colm_struct_new( prg, prg->rtd->global_id ) ;
}

void vm_init( program_t *prg )
{
	struct stack_block *b = malloc( sizeof(struct stack_block) );
	b->data = malloc( sizeof(tree_t*) * VM_STACK_SIZE );
	b->len = VM_STACK_SIZE;
	b->offset = 0;
	b->next = 0;

	prg->stack_block = b;

	prg->sb_beg = prg->stack_block->data;
	prg->sb_end = prg->stack_block->data + prg->stack_block->len;

	prg->stack_root = prg->sb_end;
}

tree_t **colm_vm_root( program_t *prg )
{
	return prg->stack_root;
}

tree_t **vm_bs_add( program_t *prg, tree_t **sp, int n )
{
	/* Close off the current block. */
	if ( prg->stack_block != 0 ) {
		prg->stack_block->offset = sp - prg->stack_block->data;
		prg->sb_total += prg->stack_block->len - prg->stack_block->offset;
	}

	if ( prg->reserve != 0 && prg->reserve->len >= n) {
		struct stack_block *b = prg->reserve;
		b->next = prg->stack_block;
		b->offset = 0;

		prg->stack_block = b;
		prg->reserve = 0;
	}
	else {
		struct stack_block *b = malloc( sizeof(struct stack_block) );
		int size = VM_STACK_SIZE;
		if ( n > size )
			size = n;
		b->next = prg->stack_block;
		b->data = malloc( sizeof(tree_t*) * size );
		b->len = size;
		b->offset = 0;

		prg->stack_block = b;
	}

	prg->sb_beg = prg->stack_block->data;
	prg->sb_end = prg->stack_block->data + prg->stack_block->len;

	return prg->sb_end;
}

tree_t **vm_bs_pop( program_t *prg, tree_t **sp, int n )
{
	while ( 1 ) {
		tree_t **end = prg->stack_block->data + prg->stack_block->len;
		int remaining = end - sp;

		/* Don't have to free this block. Remaining values to pop leave us
		 * inside it. */
		if ( n < remaining ) {
			sp += n;
			return sp;
		}

		if ( prg->stack_block->next == 0 ) {
			/* Don't delete the sentinal stack block. Returns the end as in the
			 * creation of the first stack block. */
			return prg->sb_end;
		}
	
		/* Clear any previous reserve. We are going to save this block as the
		 * reserve. */
		if ( prg->reserve != 0 ) {
			free( prg->reserve->data );
			free( prg->reserve );
		}

		/* Pop the stack block. */
		struct stack_block *b = prg->stack_block;
		prg->stack_block = prg->stack_block->next;
		prg->reserve = b;

		/* Setup the bounds. Note that we restore the full block, which is
		 * necessary to honour any CONTIGUOUS statements that counted on it
		 * before a subsequent CONTIGUOUS triggered a new block. */
		prg->sb_beg = prg->stack_block->data; 
		prg->sb_end = prg->stack_block->data + prg->stack_block->len;

		/* Update the total stack usage. */
		prg->sb_total -= prg->stack_block->len - prg->stack_block->offset;

		n -= remaining;
		sp = prg->stack_block->data + prg->stack_block->offset;
	}
}

void vm_clear( program_t *prg )
{
	while ( prg->stack_block != 0 ) {
		struct stack_block *b = prg->stack_block;
		prg->stack_block = prg->stack_block->next;
		
		free( b->data );
		free( b );
	}

	if ( prg->reserve != 0 ) {
		free( prg->reserve->data );
		free( prg->reserve );
	}
}

tree_t *colm_return_val( struct colm_program *prg )
{
	return prg->return_val;
}

void colm_set_debug( program_t *prg, long active_realm )
{
	prg->active_realm = active_realm;
}

void colm_set_reduce_clean( struct colm_program *prg, unsigned char reduce_clean )
{
	prg->reduce_clean = reduce_clean;
}

program_t *colm_new_program( struct colm_sections *rtd )
{
	program_t *prg = malloc(sizeof(program_t));
	memset( prg, 0, sizeof(program_t) );

	assert( sizeof(str_t)      <= sizeof(tree_t) );
	assert( sizeof(pointer_t)  <= sizeof(tree_t) );

	prg->rtd = rtd;
	prg->ctx_dep_parsing = 1;
	prg->reduce_clean = 1;

	init_pool_alloc( &prg->kid_pool, sizeof(kid_t) );
	init_pool_alloc( &prg->tree_pool, sizeof(tree_t) );
	init_pool_alloc( &prg->parse_tree_pool, sizeof(parse_tree_t) );
	init_pool_alloc( &prg->head_pool, sizeof(head_t) );
	init_pool_alloc( &prg->location_pool, sizeof(location_t) );

	prg->true_val = (tree_t*) 1;
	prg->false_val = (tree_t*) 0;

	/* Allocate the global variable. */
	colm_alloc_global( prg );

	/* Allocate the VM stack. */
	vm_init( prg );

	rtd->init_need();

	prg->stream_fns = malloc( sizeof(char*) * 1 );
	prg->stream_fns[0] = 0;
	return prg;
}

void colm_run_program2( program_t *prg, int argc, const char **argv, const int *argl )
{
	if ( prg->rtd->root_code_len == 0 )
		return;

	/* Make the arguments available to the program. */
	prg->argc = argc;
	prg->argv = argv;
	prg->argl = argl;

	execution_t execution;
	memset( &execution, 0, sizeof(execution) );
	execution.frame_id = prg->rtd->root_frame_id;

	colm_execute( prg, &execution, prg->rtd->root_code );

	/* Clear the arg and stack. */
	prg->argc = 0;
	prg->argv = 0;
}

void colm_run_program( program_t *prg, int argc, const char **argv )
{
	colm_run_program2( prg, argc, argv, 0 );
}

static void colm_clear_heap( program_t *prg, tree_t **sp )
{
	struct colm_struct *hi = prg->heap.head;
	while ( hi != 0 ) {
		struct colm_struct *next = hi->next;
		colm_struct_delete( prg, sp, hi );
		hi = next;
	}
}

void *colm_get_reduce_ctx( struct colm_program *prg )
{
	return prg->red_ctx;
}

void colm_set_reduce_ctx( struct colm_program *prg, void *ctx )
{
	prg->red_ctx = ctx;
}

const char **colm_extract_fns( struct colm_program *prg )
{
	const char **fns = prg->stream_fns;
	prg->stream_fns = 0;
	return fns;
}

const char *colm_error( struct colm_program *prg, int *length )
{
	const char *rtn = 0;
	if ( prg->error != 0 ) {
		rtn = prg->error->tokdata->data;
		if ( length != 0 )
			*length = prg->error->tokdata->length;
	}
	return rtn;
}

int colm_delete_program( program_t *prg )
{
	tree_t **sp = prg->stack_root;
	int exit_status = prg->exit_status;

	colm_tree_downref( prg, sp, prg->return_val );
	colm_clear_heap( prg, sp );

	colm_tree_downref( prg, sp, prg->error );

#if DEBUG
	long kid_lost = kid_num_lost( prg );
	long tree_lost = tree_num_lost( prg );
	long parse_tree_lost = parse_tree_num_lost( &prg->parse_tree_pool );
	long head_lost = head_num_lost( prg );
	long location_lost = location_num_lost( prg );

	if ( kid_lost )
		message( "warning: lost kids: %ld\n", kid_lost );

	if ( tree_lost )
		message( "warning: lost trees: %ld\n", tree_lost );

	if ( parse_tree_lost )
		message( "warning: lost parse trees: %ld\n", parse_tree_lost );

	if ( head_lost )
		message( "warning: lost heads: %ld\n", head_lost );

	if ( location_lost )
		message( "warning: lost locations: %ld\n", location_lost );
#endif

	kid_clear( prg );
	tree_clear( prg );
	head_clear( prg );
	parse_tree_clear( &prg->parse_tree_pool );
	location_clear( prg );

	struct run_buf *rb = prg->alloc_run_buf;
	while ( rb != 0 ) {
		struct run_buf *next = rb->next;
		free( rb );
		rb = next;
	}

	vm_clear( prg );

	if ( prg->stream_fns ) {
		char **ptr = (char**)prg->stream_fns;
		while ( *ptr != 0 ) {
			free( *ptr );
			ptr += 1;
		}

		free( prg->stream_fns );
	}

	free( prg );

	return exit_status;
}
