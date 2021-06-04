/*
 * Copyright 2007-2018 Adrian Thurston <thurston@colm.net>
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
#include <stdlib.h>
#include <assert.h>

#include <colm/pdarun.h>
#include <colm/program.h>
#include <colm/struct.h>
#include <colm/bytecode.h>

static void colm_list_add_after( list_t *list, list_el_t *prev_el, list_el_t *new_el );
static void colm_list_add_before( list_t *list, list_el_t *next_el, list_el_t *new_el);
list_el_t *colm_list_detach( list_t *list, list_el_t *el );

void colm_list_prepend( list_t *list, list_el_t *new_el )
{
	colm_list_add_before( list, list->head, new_el );
}

void colm_list_append( list_t *list, list_el_t *new_el )
{
	colm_list_add_after( list, list->tail, new_el );
}

list_el_t *colm_list_detach_head( list_t *list )
{
	return colm_list_detach( list, list->head );
}

list_el_t *colm_list_detach_tail( list_t *list )
{
	return colm_list_detach( list, list->tail );
}

long colm_list_length( list_t *list )
{
	return list->list_len;
}

void colm_vlist_append( struct colm_program *prg, list_t *list, value_t value )
{
	struct colm_struct *s = colm_struct_new( prg, list->generic_info->el_struct_id );

	colm_struct_set_field( s, value_t, 0, value );

	list_el_t *list_el = colm_struct_get_addr( s, list_el_t*, list->generic_info->el_offset );

	colm_list_append( list, list_el );
}

void colm_vlist_prepend( struct colm_program *prg, list_t *list, value_t value )
{
	struct colm_struct *s = colm_struct_new( prg, list->generic_info->el_struct_id );

	colm_struct_set_field( s, value_t, 0, value );

	list_el_t *list_el = colm_struct_get_addr( s, list_el_t*, list->generic_info->el_offset );

	colm_list_prepend( list, list_el );
}

value_t colm_vlist_detach_tail( struct colm_program *prg, list_t *list )
{
	list_el_t *list_el = list->tail;
	colm_list_detach( list, list_el );

	struct colm_struct *s = colm_generic_el_container( prg, list_el,
			(list->generic_info - prg->rtd->generic_info) );

	value_t val = colm_struct_get_field( s, value_t, 0 );

	if ( list->generic_info->value_type == TYPE_TREE )
		colm_tree_upref( prg, (tree_t*)val );

	return val;
}

value_t colm_vlist_detach_head( struct colm_program *prg, list_t *list )
{
	list_el_t *list_el = list->head;
	colm_list_detach( list, list_el );

	struct colm_struct *s = colm_generic_el_container( prg, list_el,
			(list->generic_info - prg->rtd->generic_info) );

	value_t val = colm_struct_get_field( s, value_t, 0 );

	if ( list->generic_info->value_type == TYPE_TREE )
		colm_tree_upref( prg, (tree_t*) val );

	return val;
}


static void colm_list_add_after( list_t *list, list_el_t *prev_el, list_el_t *new_el )
{
	/* Set the previous pointer of new_el to prev_el. We do
	 * this regardless of the state of the list. */
	new_el->list_prev = prev_el; 

	/* Set forward pointers. */
	if (prev_el == 0) {
		/* There was no prev_el, we are inserting at the head. */
		new_el->list_next = list->head;
		list->head = new_el;
	} 
	else {
		/* There was a prev_el, we can access previous next. */
		new_el->list_next = prev_el->list_next;
		prev_el->list_next = new_el;
	} 

	/* Set reverse pointers. */
	if (new_el->list_next == 0) {
		/* There is no next element. Set the tail pointer. */
		list->tail = new_el;
	}
	else {
		/* There is a next element. Set it's prev pointer. */
		new_el->list_next->list_prev = new_el;
	}

	/* Update list length. */
	list->list_len++;
}

static void colm_list_add_before( list_t *list, list_el_t *next_el, list_el_t *new_el)
{
	/* Set the next pointer of the new element to next_el. We do
	 * this regardless of the state of the list. */
	new_el->list_next = next_el; 

	/* Set reverse pointers. */
	if (next_el == 0) {
		/* There is no next elememnt. We are inserting at the tail. */
		new_el->list_prev = list->tail;
		list->tail = new_el;
	} 
	else {
		/* There is a next element and we can access next's previous. */
		new_el->list_prev = next_el->list_prev;
		next_el->list_prev = new_el;
	} 

	/* Set forward pointers. */
	if (new_el->list_prev == 0) {
		/* There is no previous element. Set the head pointer.*/
		list->head = new_el;
	}
	else {
		/* There is a previous element, set it's next pointer to new_el. */
		new_el->list_prev->list_next = new_el;
	}

	list->list_len++;
}

list_el_t *colm_list_detach( list_t *list, list_el_t *el )
{
	/* Set forward pointers to skip over el. */
	if (el->list_prev == 0) 
		list->head = el->list_next; 
	else
		el->list_prev->list_next = el->list_next; 

	/* Set reverse pointers to skip over el. */
	if (el->list_next == 0) 
		list->tail = el->list_prev; 
	else
		el->list_next->list_prev = el->list_prev; 

	/* Update List length and return element we detached. */
	list->list_len--;
	return el;
}

void colm_list_destroy( struct colm_program *prg, tree_t **sp, struct colm_struct *s )
{
}

list_t *colm_list_new( struct colm_program *prg )
{
	size_t memsize = sizeof(struct colm_list);
	struct colm_list *list = (struct colm_list*) malloc( memsize );
	memset( list, 0, memsize );
	colm_struct_add( prg, (struct colm_struct *)list );
	list->id = prg->rtd->struct_inbuilt_id;
	list->destructor = &colm_list_destroy;
	return list;
}

struct colm_struct *colm_list_get( struct colm_program *prg,
		list_t *list, word_t gen_id, word_t field )
{
	struct generic_info *gi = &prg->rtd->generic_info[gen_id];
	list_el_t *result = 0;
	switch ( field ) {
		case 0: 
			result = list->head;
			break;
		case 1: 
			result = list->tail;
			break;
		default:
			assert( 0 );
			break;
	}

	struct colm_struct *s = result != 0 ?
			colm_struct_container( result, gi->el_offset ) : 0;
	return s;
}

struct colm_struct *colm_list_el_get( struct colm_program *prg,
		list_el_t *list_el, word_t gen_id, word_t field )
{
	struct generic_info *gi = &prg->rtd->generic_info[gen_id];
	list_el_t *result = 0;
	switch ( field ) {
		case 0: 
			result = list_el->list_prev;
			break;
		case 1: 
			result = list_el->list_next;
			break;
		default:
			assert( 0 );
			break;
	}

	struct colm_struct *s = result != 0 ?
			colm_struct_container( result, gi->el_offset ) : 0;
	return s;
}
