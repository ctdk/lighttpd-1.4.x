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

#include "stream.h"

#include "mod_cml.h"

/* init the plugin data */
INIT_FUNC(mod_cml_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	p->basedir         = buffer_init();
	p->baseurl         = buffer_init();
	p->session_id      = buffer_init();
	p->trigger_handler = buffer_init();
	
	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_cml_free) {
	plugin_data *p = p_d;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			buffer_free(s->ext);
			
			buffer_free(s->mc_namespace);
			array_free(s->mc_hosts);
			
#if defined(HAVE_MEMCACHE_H)
			if (s->mc) mc_free(s->mc);
#endif
			
			free(s);
		}
		free(p->config_storage);
	}
	
	buffer_free(p->trigger_handler);
	buffer_free(p->session_id);
	buffer_free(p->basedir);
	buffer_free(p->baseurl);
	
	free(p);
	
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_cml_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ "cml.extension",              NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ "cml.memcache-hosts",         NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },        /* 1 */
		{ "cml.memcache-namespace",     NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = malloc(srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = malloc(sizeof(plugin_config));
		s->ext    = buffer_init();
		s->mc_hosts       = array_init();
		s->mc_namespace   = buffer_init();
#if defined(HAVE_MEMCACHE_H)
		s->mc = NULL;
#endif
		
		cv[0].destination = s->ext;
		cv[1].destination = s->mc_hosts;
		cv[2].destination = s->mc_namespace;
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
		
		if (s->mc_hosts->used) {
#if defined(HAVE_MEMCACHE_H)
			size_t k;
			s->mc = mc_new();
		
			for (k = 0; k < s->mc_hosts->used; k++) {
				data_string *ds = (data_string *)s->mc_hosts->data[k];
				
				if (0 != mc_server_add4(s->mc, ds->value->ptr)) {
					log_error_write(srv, __FILE__, __LINE__, "sb", 
							"connection to host failed:", 
							ds->value);
					
					return HANDLER_ERROR;
				}
			}
#else
			log_error_write(srv, __FILE__, __LINE__, "s", 
					"memcache support is not compiled in but cml.memcache-hosts is set, aborting");
			return HANDLER_ERROR;
#endif
		}
	}
	
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_cml_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	
	PATCH(ext);
#if defined(HAVE_MEMCACHE_H)
	PATCH(mc);
#endif
	PATCH(mc_namespace);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("cml.extension"))) {
				PATCH(ext);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("cml.memcache-hosts"))) {
#if defined(HAVE_MEMCACHE_H)
				PATCH(mc);
#endif
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN("cml.memcache-namespace"))) {
				PATCH(mc_namespace);
			}
		}
	}
	
	return 0;
}
#undef PATCH


int cache_get_cookie_session_id(server *srv, connection *con, plugin_data *p) {
	data_unset *d;

	UNUSED(srv);
	
	if (NULL != (d = array_get_element(con->request.headers, "Cookie"))) {
		data_string *ds = (data_string *)d;
		size_t key = 0, value = 0;
		size_t is_key = 1, is_sid = 0;
		size_t i;
		
		/* found COOKIE */
		if (!DATA_IS_STRING(d)) return -1;
		if (ds->value->used == 0) return -1;
			
		if (ds->value->ptr[0] == '\0' ||
		    ds->value->ptr[0] == '=' ||
		    ds->value->ptr[0] == ';') return -1;
		
		buffer_reset(p->session_id);
		for (i = 0; i < ds->value->used; i++) {
			switch(ds->value->ptr[i]) {
			case '=':
				if (is_key) {
					if (0 == strncmp(ds->value->ptr + key, "PHPSESSID", i - key)) {
						/* found PHP-session-id-key */
						is_sid = 1;
					}
					value = i + 1;
				
					is_key = 0;
				}
				
				break;
			case ';':
				if (is_sid) {
					buffer_copy_string_len(p->session_id, ds->value->ptr + value, i - value);
				}
				
				is_sid = 0;
				key = i + 1;
				value = 0;
				is_key = 1;
				break;
			case ' ':
				if (is_key == 1 && key == i) key = i + 1;
				if (is_key == 0 && value == i) value = i + 1;
				break;
			case '\0':
				if (is_sid) {
					buffer_copy_string_len(p->session_id, ds->value->ptr + value, i - value);
				}
				/* fin */
				break;
			}
		}
	}
	
	return !buffer_is_empty(p->session_id);
}

int cache_get_url_session_id(server *srv, connection *con, plugin_data *p) {
	size_t key = 0, value = 0;
	size_t is_key = 1, is_sid = 0;
	size_t i;
	
	UNUSED(srv);
	buffer_reset(p->session_id);
	for (i = 0; i < con->uri.query->used; i++) {
		switch(con->uri.query->ptr[i]) {
		case '=':
			if (is_key) {
				if (0 == strncmp(con->uri.query->ptr + key, "PHPSESSID", i - key)) {
					/* found PHP-session-id-key */
						is_sid = 1;
				}
				value = i + 1;
				
				is_key = 0;
			}
			
			break;
		case '&':
			if (is_sid) {
				buffer_copy_string_len(p->session_id, con->uri.query->ptr + value, i - value);
			}
			
			is_sid = 0;
			key = i + 1;
			value = 0;
			is_key = 1;
			break;
		case ' ':
			if (is_key == 1 && key == i) key = i + 1;
			if (is_key == 0 && value == i) value = i + 1;
			break;
		case '\0':
			if (is_sid) {
				buffer_copy_string_len(p->session_id, con->uri.query->ptr + value, i - value);
			}
			/* fin */
			break;
		}
	}

	return !buffer_is_empty(p->session_id);
}

int cache_get_session_id(server *srv, connection *con, plugin_data *p) {
	
	return cache_get_cookie_session_id(srv, con, p) || 
		cache_get_url_session_id(srv, con, p);
	
}


URIHANDLER_FUNC(mod_cml_is_handled) {
	int ct_len, s_len;
	buffer *b;
	char *c;
	buffer *fn = con->physical.path;
	plugin_data *p = p_d;
	int ret;
	
	if (fn->used == 0) return HANDLER_ERROR;
	
	mod_cml_patch_connection(srv, con, p);
	
	buffer_reset(p->basedir);
	buffer_reset(p->baseurl);
	buffer_reset(p->session_id);
	buffer_reset(p->trigger_handler);
	
	if (buffer_is_empty(p->conf.ext)) return HANDLER_GO_ON;
	
	ct_len = p->conf.ext->used - 1;
	s_len = fn->used - 1;
	
	if (s_len < ct_len) return HANDLER_GO_ON;
	
	if (0 != strncmp(fn->ptr + s_len - ct_len, p->conf.ext->ptr, ct_len)) {
		/* not my job */
		return HANDLER_GO_ON;
	}
	
	/* cleanup basedir */
	b = p->baseurl;
	buffer_copy_string_buffer(b, con->uri.path);
	for (c = b->ptr + b->used - 1; c > b->ptr && *c != '/'; c--);
	
	if (*c == '/') {
		b->used = c - b->ptr + 2;
		*(c+1) = '\0';
	}
	
	b = p->basedir;
	buffer_copy_string_buffer(b, fn);
	for (c = b->ptr + b->used - 1; c > b->ptr && *c != '/'; c--);
	
	if (*c == '/') {
		b->used = c - b->ptr + 2;
		*(c+1) = '\0';
	}
	
	/* prepare variables
	 * - session-id
	 *   - cookie-based
	 *   - get-param-based
	 */
	
	cache_get_session_id(srv, con, p);
	
	ret = cache_parse_lua(srv, con, p, fn);
	
	switch(ret) {
	case -1:
		/* error */
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "s", "cache-error");
		}
		con->http_status = 500;
		return HANDLER_COMEBACK;
	case 0:
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "s", "cache-hit");
		}
		/* cache-hit */
		buffer_reset(con->physical.path);
		return HANDLER_FINISHED;
	case 1:
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__, "s", "cache-miss");
		}
		/* cache miss */
		return HANDLER_COMEBACK;
	}
	
	return 0;
}

int mod_cml_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("cache");
	
	p->init        = mod_cml_init;
	p->cleanup     = mod_cml_free;
	p->set_defaults  = mod_cml_set_defaults;
	
	p->handle_subrequest_start = mod_cml_is_handled;
	
	p->data        = NULL;
	
	return 0;
}
