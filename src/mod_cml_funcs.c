#include <sys/stat.h>
#include <time.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "buffer.h"
#include "server.h"
#include "log.h"
#include "plugin.h"
#include "response.h"

#include "mod_cml.h"


CACHE_FUNC_PROTO(f_unix_time_now) {
	UNUSED(srv);
	UNUSED(con);
	UNUSED(p);
	
	VAL_LONG(result) = srv->cur_ts;
	
	return 0;
}

CACHE_FUNC_PROTO(f_file_mtime) {
	buffer *b;
	struct stat st;
	
	UNUSED(con);
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_file_mtime: I need a string:", 
				p->params->ptr[0]->type);
		
		return -1;
	}
	
	b = buffer_init();
			
	/* build filename */
	buffer_copy_string_buffer(b, p->basedir);
	buffer_append_string_buffer(b, p->params->ptr[0]->data.str);
	
	if (-1 == stat(b->ptr, &st)) {
		log_error_write(srv, __FILE__, __LINE__, "sbs", 
				"trigger.if file.mtime():", b, strerror(errno));
		
		buffer_free(b);
		return -1;
	}
	buffer_free(b);
	
	tnode_prepare_long(result);
	VAL_LONG(result) = st.st_mtime;
	
	return 0;
}

#ifdef HAVE_MEMCACHE_H
CACHE_FUNC_PROTO(f_memcache_exists) {
	char *r;
	
	UNUSED(con);
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_exists: I need a string:", 
				p->params->ptr[0]->type);
		
		return -1;
	}
	
	tnode_prepare_long(result);
	
	if (NULL == (r = mc_aget(p->conf.mc, 
				 CONST_BUF_LEN(p->params->ptr[0]->data.str)))) {
				
		VAL_LONG(result) = 0;
		return 0;
	}
	
	free(r);
	
	VAL_LONG(result) = 1;
	
	return 0;
}

CACHE_FUNC_PROTO(f_memcache_get_string) {
	char *r;
	
	UNUSED(con);
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_get: I need a string:", 
				p->params->ptr[0]->type);
		return -1;
	}
	
	log_error_write(srv, __FILE__, __LINE__, "sb", 
				"f_memcache_get: couldn't find:", 
				p->params->ptr[0]->data.str);
	
	if (NULL == (r = mc_aget(p->conf.mc, 
				p->params->ptr[0]->data.str->ptr, p->params->ptr[0]->data.str->used - 1))) {
		log_error_write(srv, __FILE__, __LINE__, "sb", 
				"f_memcache_get: couldn't find:", 
				p->params->ptr[0]->data.str);
		return -1;
	}
	tnode_prepare_string(result);
	buffer_copy_string(VAL_STRING(result), r);
	
	free(r);
	
	return 0;
}

CACHE_FUNC_PROTO(f_memcache_get_long) {
	char *r;
	
	UNUSED(con);
	
	if (p->params->ptr[0]->type != T_NODE_VALUE_STRING) {
		log_error_write(srv, __FILE__, __LINE__, "sd", 
				"f_memcache_get: I need a string:", 
				p->params->ptr[0]->type);
		return -1;
	}
	
	
	
	if (NULL == (r = mc_aget(p->conf.mc, 
				 CONST_BUF_LEN(p->params->ptr[0]->data.str)))) {
		log_error_write(srv, __FILE__, __LINE__, "sb", 
				"f_memcache_get: couldn't find:", 
				p->params->ptr[0]->data.str);
		return -1;
	}
	
	tnode_prepare_long(result);
	VAL_LONG(result) = strtol(r, NULL, 10);
	
	free(r);
	
	return 0;
}
#endif
