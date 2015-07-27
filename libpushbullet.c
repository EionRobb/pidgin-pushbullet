#define PURPLE_PLUGINS

// Glib
#include <glib.h>

// GNU C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif

#include <json-glib/json-glib.h>

#include <accountopt.h>
#include <debug.h>
#include <prpl.h>
#include <version.h>

#define PB_IS_SMS(a) (((a[0] == '+' || a[0] == '(') && g_ascii_isdigit(a[1])) || g_ascii_isdigit(a[0]))

typedef struct {
	gchar *access_token;
	PurpleSslConnection *websocket;
	PurpleAccount *account;
	PurpleConnection *pc;
	gchar *main_sms_device;
	gchar *iden;
	
	guint phone_threads_poll;
	guint everything_poll;
} PushBulletAccount;

typedef void (*PushBulletProxyCallbackFunc)(PushBulletAccount *pba, JsonNode *node, gpointer user_data);

typedef struct {
	PushBulletAccount *pba;
	PushBulletProxyCallbackFunc callback;
	gpointer user_data;
} PushBulletProxyConnection;


static gchar *
pb_jsonobj_to_string(JsonObject *jsonobj)
{
	JsonGenerator *generator;
	JsonNode *root;
	gchar *string;
	
	root = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(root, jsonobj);
	
	generator = json_generator_new();
	json_generator_set_root(generator, root);
	
	string = json_generator_to_data(generator, NULL);
	
	g_object_unref(generator);
	json_node_free(root);
	
	return string;
}

static const gchar *
pb_normalise_clean(const PurpleAccount *account, const char *who)
{
	static gchar normalised[100];
	gint i, len, next = 0;
	memset(normalised, 0, sizeof(normalised));
	
	len = strlen(who);
	if (PB_IS_SMS(who))
	{
		for(i = 0; i < len && i < sizeof(normalised); i++)
		{
			//strip out anything not a number
			if ((who[i] >= '0' && who[i] <= '9') || who[i] == '+')
				normalised[next++] = who[i];
		}
	} else {
		memcpy(normalised, who, MIN(len, sizeof(normalised)));
		purple_str_strip_char(normalised, ' ');
	}
	
	return normalised;
}

static void
pb_response_callback(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	PushBulletProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();
	
	if (!json_parser_load_from_data(parser, url_text, len, NULL))
	{
		purple_debug_error("pushbullet", "Error parsing response: %s\n", url_text);
		if (conn->callback) {
			conn->callback(conn->pba, NULL, conn->user_data);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);
		
		//purple_debug_misc("pushbullet", "Got response: %s\n", url_text);
		if (conn->callback) {
			conn->callback(conn->pba, root, conn->user_data);
		}
	}
	
	g_object_unref(parser);
	g_free(conn);
}

static void
pb_fetch_url(PushBulletAccount *pba, const gchar *url, const gchar *postdata, PushBulletProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	GString *headers;
    gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
    int port;
	PurpleProxyInfo *proxy_info;
	gchar *proxy_url;
	PushBulletProxyConnection *conn;
	
	account = pba->account;
	if (purple_account_is_disconnected(account)) return;
	
	conn = g_new0(PushBulletProxyConnection, 1);
	conn->pba = pba;
	conn->callback = callback;
	conn->user_data = user_data;
    
    purple_url_parse(url, &host, &port, &path, &user, &password);
	purple_debug_info("pushbullet", "Fetching url %s\n", url);
	
	headers = g_string_new(NULL);
	
	proxy_info = purple_proxy_get_setup(account);
	if (purple_proxy_info_get_type(proxy_info) == PURPLE_PROXY_USE_GLOBAL)
		proxy_info = purple_global_proxy_get_info();
	if (purple_proxy_info_get_type(proxy_info) == PURPLE_PROXY_HTTP)
	{
		g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), url);
		proxy_url = g_strdup_printf("http://%s:%d", purple_proxy_info_get_host(proxy_info), purple_proxy_info_get_port(proxy_info));
	} else {
		//Use the full 'url' until libpurple can handle path's longer than 256 chars
		g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), path);
		//g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), url);
		proxy_url = g_strdup(url);
	}
    g_string_append_printf(headers, "Connection: close\r\n");
    g_string_append_printf(headers, "Host: %s\r\n", host);
    g_string_append_printf(headers, "Accept: */*\r\n");
	g_string_append_printf(headers, "User-Agent: Pidgin\r\n");
    
    if(pba->access_token && *(pba->access_token)) {
        g_string_append_printf(headers, "Authorization: Bearer %s\r\n", pba->access_token);
    }
    
    if(postdata) {
		purple_debug_info("mightytext", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			g_string_append(headers, "Content-Type: application/json\r\n");
		} else {
			g_string_append(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
		}
        g_string_append_printf(headers, "Content-Length: %d\r\n", strlen(postdata));
        g_string_append(headers, "\r\n");
        
        g_string_append(headers, postdata);
    } else {
        g_string_append(headers, "\r\n");
    }
	
	//purple_debug_misc("pushbullet", "Request headers are %s\n", headers->str);
    
    g_free(host);
    g_free(path);
    g_free(user);
    g_free(password);
    
    purple_util_fetch_url_request_len_with_account(pba->account, proxy_url, FALSE, "Pidgin", TRUE, headers->str, FALSE, 6553500, pb_response_callback, conn);
	
	g_string_free(headers, TRUE);
	g_free(proxy_url);
}

static void
pba_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	
}

static void
pba_socket_got_header_response(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	PushBulletAccount *pba = userdata;
	purple_ssl_input_add(pba->websocket, pba_socket_got_data, pba);
	
	// HTTP/1.1 101 Switching Protocols
	// Server: nginx
	// Date: Sun, 19 Jul 2015 23:44:27 GMT
	// Connection: upgrade
	// Upgrade: websocket
	// Sec-WebSocket-Accept: pUDN5Js0uDN5KhEWoPJGLyTqwME=
	// Expires: 0
	// Cache-Control: no-cache
}

static void
pb_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	PushBulletAccount *pba = userdata;
	gchar *websocket_header;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy
	
	purple_ssl_input_add(pba->websocket, pba_socket_got_header_response, pba);
	
	websocket_header = g_strdup_printf("GET /subscribe/%s HTTP/1.1\r\n"
							"Host: stream.pushbullet.com\r\n"
							"Connection: Upgrade\r\n"
							"Pragma: no-cache\r\n"
							"Cache-Control: no-cache\r\n"
							"Upgrade: websocket\r\n"
							"Sec-WebSocket-Version: 13\r\n"
							"Sec-WebSocket-Key: %s\r\n"
							//"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
							"\r\n", pba->access_token, websocket_key);
	
	purple_ssl_write(pba->websocket, websocket_header, strlen(websocket_header));
	
	g_free(websocket_header);
}

static void
pb_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
	PushBulletAccount *pba = userdata;
}

static void
pb_start_socket(PushBulletAccount *pba)
{
	// GET /subscribe/%s HTTP/1.1
	// Host: stream.pushbullet.com
	// Connection: Upgrade
	// Pragma: no-cache
	// Cache-Control: no-cache
	// Upgrade: websocket
	// Sec-WebSocket-Version: 13
	// Sec-WebSocket-Key: abc123
	// Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
	
	pba->websocket = purple_ssl_connect(pba->account, "stream.pushbullet.com", 443, pb_socket_connected, pb_socket_failed, pba);
}


static int 
pb_send_im(PurpleConnection *pc, const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
	PushBulletAccount *pba = pc->proto_data;
	gchar *stripped, *postdata;
	
	if (g_str_has_prefix(message, "?OTR"))
		return 0;
	
	if (PB_IS_SMS(who))
	{
		JsonObject *root = json_object_new();
		JsonObject *push = json_object_new();
		
		//json_object_set_string_member(push, "guid", ""); //TODO unique id for message
		json_object_set_string_member(push, "type", "messaging_extension_reply");
		json_object_set_string_member(push, "package_name", "com.pushbullet.android");
		//json_object_set_string_member(push, "source_user_iden", pba->iden); //TODO supply this
		json_object_set_string_member(push, "target_device_iden", pba->main_sms_device);
		json_object_set_string_member(push, "conversation_iden", who);
		
		stripped = g_strstrip(purple_markup_strip_html(message));
		json_object_set_string_member(push, "message", stripped);
		g_free(stripped);
		
		json_object_set_object_member(root, "push", push);
		json_object_set_string_member(root, "type", "push");
		
		postdata = pb_jsonobj_to_string(root);
		pb_fetch_url(pba, "https://api.pushbullet.com/v2/ephemerals", postdata, NULL, NULL);
		g_free(postdata);
		
		json_object_unref(root);
		
		return 1;
	}
	
	if (!strchr(who, '@')) {
		return -1;
	}
	
	//<IMG ID="5"> - embedded image i.e. MMS
	
	/* Image flow:
	POST to https://api.pushbullet.com/v3/start-upload {"name":"imagename.jpg","size":12345,"type":"image/jpeg"}
	=> {"id":"abcde","piece_size":5242880,"piece_urls":["https://upload.pushbullet.com/upload-piece/12345/0"]}
	
	POST data in chunks to the pieces_urls
	
	POST to https://api.pushbullet.com/v3/finish-upload {"id":"abcde"} (from earlier)
	=> {"file_name":"imagename.jpg","file_type":"image/jpeg","file_url":"..urltoimage..."}
	
	POST to https://api.pushbullet.com/v2/pushes {"type":"file","file_name":"filename.jpg","file_url":"..urltoimage...","file_type":"image/jpeg","email":"touser"}
	*/
	
	{
		JsonObject *root = json_object_new();
		//json_object_set_string_member(root, "guid", ""); //TODO unique id for message
		json_object_set_string_member(root, "type", "note");
		json_object_set_string_member(root, "title", "");
		json_object_set_string_member(root, "url", "");
		json_object_set_string_member(root, "email", who);
		
		stripped = g_strstrip(purple_markup_strip_html(message));
		json_object_set_string_member(root, "body", stripped);
		g_free(stripped);
		
		postdata = pb_jsonobj_to_string(root);
		pb_fetch_url(pba, "https://api.pushbullet.com/v2/pushes", postdata, NULL, NULL);
		g_free(postdata);
		
		json_object_unref(root);
		
		return 1;
	}
	
	return -1;
}

static gboolean
pb_offline_msg(const PurpleBuddy *buddy)
{
	return TRUE;
}

static void
pb_got_phone_thread(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	PurpleAccount *account = pba->account;
	PurpleConnection *pc = pba->pc;
	JsonObject *rootobj = json_node_get_object(node);
	JsonArray *thread = json_object_get_array_member(rootobj, "thread");
	gint i;
	guint len;
	gchar *from = user_data;
	PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, account);
	gint purple_last_message_timestamp = purple_account_get_int(account, "last_message_timestamp", 0);
	gint newest_phone_message_id = purple_account_get_int(account, "newest_phone_message_id", 0);
	
	for(i = json_array_get_length(thread); i > 0; i--)
	{
		JsonObject *message = json_array_get_object_element(thread, i - 1);
		gint64 timestamp = json_object_get_int_member(message, "timestamp");
		const gchar *direction = json_object_get_string_member(message, "direction");
		const gchar *body = json_object_get_string_member(message, "body");
		gint id = atoi(json_object_get_string_member(message, "id"));
		
		if (timestamp > purple_last_message_timestamp || id > newest_phone_message_id) {
			gchar *body_html = purple_strdup_withhtml(body);
			if (direction[0] != 'o') {
				serv_got_im(pc, from, body_html, PURPLE_MESSAGE_RECV, timestamp);
			} else {
				//const gchar *guid = json_object_get_string_member(message, "guid"); //TODO check sent guids
				if (conv == NULL)
				{
					conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from);
				}
				purple_conversation_write(conv, from, body_html, PURPLE_MESSAGE_SEND, timestamp);
			}
			g_free(body_html);
			
			purple_account_set_int(account, "last_message_timestamp", MAX(purple_account_get_int(account, "last_message_timestamp", 0), timestamp));
			purple_account_set_int(account, "newest_phone_message_id", MAX(purple_account_get_int(account, "newest_phone_message_id", 0), id));
		}
	}
	
	g_free(from);
}

static void
pb_get_phone_thread_by_id(PushBulletAccount *pba, const gchar *device, const gchar *id, const gchar *from)
{
	gchar *thread_url;
	gchar *from_copy;
	
	if (id == NULL || id[0] == '\0')
		return;
	
	if (device == NULL) {
		device = pba->main_sms_device;
	}
	from_copy = g_strdup(from);

	thread_url = g_strdup_printf("https://api.pushbullet.com/v2/permanents/%s_thread_%s?",
									purple_url_encode(device), id);
	
	pb_fetch_url(pba, thread_url, NULL, pb_got_phone_thread, from_copy);
	
	g_free(thread_url);
}

static void
pb_got_phone_threads(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	PurpleAccount *account = pba->account;
	JsonObject *rootobj = json_node_get_object(node);
	JsonArray *threads = json_object_get_array_member(rootobj, "threads");
	gint i;
	guint len;
	gchar *device = user_data;
	gint last_message_timestamp = purple_account_get_int(account, "last_message_timestamp", 0);
	gint newest_phone_message_id = purple_account_get_int(account, "newest_phone_message_id", 0);
	
	for(i = 0, len = json_array_get_length(threads); i < len; i++)
	{
		JsonObject *thread = json_array_get_object_element(threads, i);
		const gchar *id = json_object_get_string_member(thread, "id");
		JsonArray *recipients = json_object_get_array_member(thread, "recipients");
		const gchar *from = NULL;
		
		if (json_array_get_length(recipients) > 0) {
			JsonObject *first_recipient = json_array_get_object_element(recipients, 0);
			from = json_object_get_string_member(first_recipient, "number");
		}
		if (from == NULL) {
			continue;
		}
		if (json_object_has_member(thread, "latest"))
		{
			JsonObject *latest = json_object_get_object_member(thread, "latest");
			gint64 timestamp = json_object_get_int_member(latest, "timestamp");
			gint msgid = atoi(json_object_get_string_member(latest, "id"));
			
			if (timestamp > last_message_timestamp || msgid > newest_phone_message_id) {
				pb_get_phone_thread_by_id(pba, device, id, from);
			}
		}
		
	}
	
	g_free(device);
}

static void
pb_get_phone_threads(PushBulletAccount *pba, const gchar *device)
{
	gchar *phonebook_url;
	gchar *device_copy;
	
	if (device == NULL) {
		device = pba->main_sms_device;
	}
	device_copy = g_strdup(device);

	phonebook_url = g_strdup_printf("https://api.pushbullet.com/v2/permanents/%s_threads",
									purple_url_encode(device_copy));
	
	pb_fetch_url(pba, phonebook_url, NULL, pb_got_phone_threads, device_copy);
	
	g_free(phonebook_url);
}

static gboolean
pb_poll_phone_threads(PushBulletAccount *pba)
{
	if (purple_account_is_connected(pba->account)) {
		pb_get_phone_threads(pba, NULL);
		return TRUE;
	}
	
	return FALSE;
}

static void
pb_got_phonebook(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	PurpleAccount *account = pba->account;
	JsonObject *rootobj = json_node_get_object(node);
	JsonArray *phonebook = json_object_get_array_member(rootobj, "phonebook");
	gint i;
	guint len;
	gchar *device = user_data;
	PurpleGroup *pbgroup;
	
	pbgroup = purple_find_group("PushBullet");
	if (!pbgroup)
	{
		pbgroup = purple_group_new("PushBullet");
		purple_blist_add_group(pbgroup, NULL);
	}
	
	for(i = 0, len = json_array_get_length(phonebook); i < len; i++)
	{
		JsonObject *number = json_array_get_object_element(phonebook, i);
		const gchar *name = json_object_get_string_member(number, "name");
		const gchar *phone = json_object_get_string_member(number, "phone");
		const gchar *phone_type = json_object_get_string_member(number, "phone_type");
		PurpleBuddy *pbuddy;
		
		//Only handle the right 'type' of phone number. 
		//home, mobile, work, other
		if (purple_account_get_bool(account, "mobile_contacts_only", FALSE) && phone_type[0] != 'm')
			continue;
		
		pbuddy = purple_find_buddy(account, phone);
		if (!pbuddy)
		{
			pbuddy = purple_buddy_new(account, phone, name);
			purple_blist_add_buddy(pbuddy, NULL, pbgroup, NULL);
			purple_debug_info("pushbullet", "Added buddy %s %s\n", phone, name);
		}
		
		purple_prpl_got_user_status(account, phone, "mobile", NULL);
		purple_prpl_got_user_status(account, phone, purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE), NULL);
	}
	
	g_free(device);
}

static void
pb_get_phonebook(PushBulletAccount *pba, const gchar *device)
{
	gchar *phonebook_url;
	gchar *device_copy;
	
	if (device == NULL) {
		device = pba->main_sms_device;
	}
	device_copy = g_strdup(device);

	phonebook_url = g_strdup_printf("https://api.pushbullet.com/v2/permanents/phonebook_%s?",
									purple_url_encode(device_copy));
	
	pb_fetch_url(pba, phonebook_url, NULL, pb_got_phonebook, device_copy);
	
	g_free(phonebook_url);
}

static void
pb_got_everything(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	JsonObject *rootobj = json_node_get_object(node);
	JsonArray *devices = json_object_get_array_member(rootobj, "devices");
	gint i;
	guint len;
	
	for(i = 0, len = json_array_get_length(devices); i < len; i++) {
		JsonObject *device = json_array_get_object_element(devices, i);
		
		if (pba->main_sms_device == NULL && json_object_get_boolean_member(device, "has_sms")) {
			pba->main_sms_device = g_strdup(json_object_get_string_member(device, "iden"));
			purple_account_set_string(pba->account, "main_sms_device", pba->main_sms_device);
			
			pb_get_phonebook(pba, pba->main_sms_device);
			break; //TODO handle more than one
		}
	}
}

static void
pb_get_everything(PushBulletAccount *pba)
{
	const gchar *everything_url = "https://api.pushbullet.com/v2/everything";
	
	pb_fetch_url(pba, everything_url, NULL, pb_got_everything, NULL);
}

static void
pb_get_everything_since(PushBulletAccount *pba, gint timestamp)
{
	gchar *everything_url = g_strdup_printf("https://api.pushbullet.com/v2/everything?modified_after=%d", timestamp);
	
	pb_fetch_url(pba, everything_url, NULL, pb_got_everything, NULL);
	
	g_free(everything_url);
}

static void
pb_login(PurpleAccount *account)
{
	PushBulletAccount *pba;
	PurpleConnection *pc;
	const gchar *password;
	
	pc = purple_account_get_connection(account);
	
	pba = g_new0(PushBulletAccount, 1);
	pba->account = account;
	pba->pc = pc;
	
	password = purple_account_get_password(account);
	if (password && *password) {
		pba->access_token = g_strdup(password);
	}
	
	pc->proto_data = pba;
	
	if(pba->access_token)
	{
		purple_connection_set_state(pc, PURPLE_CONNECTED);
		
		if (purple_account_get_string(account, "main_sms_device", NULL) != NULL) {
			pba->main_sms_device = g_strdup(purple_account_get_string(account, "main_sms_device", NULL));
			pb_get_phonebook(pba, pba->main_sms_device);
			
			pb_poll_phone_threads(pba);
			pba->phone_threads_poll = purple_timeout_add_seconds(10, (GSourceFunc) pb_poll_phone_threads, pba);
		}
		
		pb_get_everything(pba);
		return;
	}
}

static void 
pb_close(PurpleConnection *pc)
{
	PushBulletAccount *pba = pc->proto_data;
	PurpleAccount *account;
	
	account = purple_connection_get_account(pc);
	
	purple_account_set_string(account, "main_sms_device", pba->main_sms_device);
	g_free(pba->main_sms_device); pba->main_sms_device = NULL;
	
	purple_timeout_remove(pba->phone_threads_poll);
	
	g_free(pba->access_token); pba->access_token = NULL;
	g_free(pba);
}

static const char *
pb_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "pushbullet";
}

static const gchar *
pb_list_emblem(PurpleBuddy *buddy)
{
	if (PB_IS_SMS(buddy->name))
		return "mobile";
	
	return "";
}

static GList *
pb_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_MOBILE, "mobile", "Online", FALSE, FALSE, TRUE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	return types;
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	return TRUE;
}

static void
plugin_init(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	PurplePluginInfo *info = plugin->info;
	PurplePluginProtocolInfo *prpl_info = info->extra_info;
	//purple_signal_connect(purple_get_core(), "uri-handler", plugin, PURPLE_CALLBACK(mightytext_uri_handler), NULL);
	
	// option = purple_account_option_bool_new("Show calls", "show_calls", TRUE);
	// prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
	
	option = purple_account_option_bool_new("Only show 'mobile' contacts", "mobile_contacts_only", FALSE);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
}

PurplePluginProtocolInfo prpl_info = {
	/* options */
	//TODO, use OPT_PROTO_IM_IMAGE for sending MMS messages
	OPT_PROTO_SLASH_COMMANDS_NATIVE/*|OPT_PROTO_IM_IMAGE*/,

	NULL,                /* user_splits */
	NULL,                /* protocol_options */
	{"png,gif,jpeg", 0, 0, 96, 96, 0, PURPLE_ICON_SCALE_SEND}, /* icon_spec */
	pb_list_icon,        /* list_icon */
	pb_list_emblem,      /* list_emblem */
	NULL,                /* status_text */
	NULL,                /* tooltip_text */
	pb_status_types,     /* status_types */
	NULL/*mt_node_menu*/,        /* blist_node_menu */
	NULL,                /* chat_info */
	NULL,                /* chat_info_defaults */
	pb_login,            /* login */
	pb_close,            /* close */
	pb_send_im,          /* send_im */
	NULL,                /* set_info */
	NULL,                /* send_typing */
	NULL,                /* get_info */
	NULL,                /* set_status */
	NULL,                /* set_idle */
	NULL,                /* change_passwd */
	NULL,                /* add_buddy */
	NULL,                /* add_buddies */
	NULL,                /* remove_buddy */
	NULL,                /* remove_buddies */
	NULL,                /* add_permit */
	NULL,                /* add_deny */
	NULL,                /* rem_permit */
	NULL,                /* rem_deny */
	NULL,                /* set_permit_deny */
	NULL,                /* join_chat */
	NULL,                /* reject chat invite */
	NULL,                /* get_chat_name */
	NULL,                /* chat_invite */
	NULL,                /* chat_leave */
	NULL,                /* chat_whisper */
	NULL,                /* chat_send */
	NULL/*mt_keepalive*/,        /* keepalive */
	NULL,                /* register_user */
	NULL,                /* get_cb_info */
	NULL,                /* get_cb_away */
	NULL,                /* alias_buddy */
	NULL,                /* group_buddy */
	NULL,                /* rename_group */
	NULL,                /* buddy_free */
	NULL,                /* convo_closed */
	pb_normalise_clean,  /* normalize */
	NULL,                /* set_buddy_icon */
	NULL,                /* remove_group */
	NULL,                /* get_cb_real_name */
	NULL,                /* set_chat_topic */
	NULL,				 /* find_blist_chat */
	NULL,                /* roomlist_get_list */
	NULL,                /* roomlist_cancel */
	NULL,                /* roomlist_expand_category */
	NULL,                /* can_receive_file */
	NULL,                /* send_file */
	NULL,                /* new_xfer */
	pb_offline_msg,      /* offline_message */
	NULL,                /* whiteboard_prpl_ops */
	NULL,                /* send_raw */
	NULL,                /* roomlist_room_serialize */
	NULL,                /* unregister_user */
	NULL,                /* send_attention */
	NULL,                /* attention_types */
#if PURPLE_MAJOR_VERSION == 2 && PURPLE_MINOR_VERSION == 1
	(gpointer)
#endif
	sizeof(PurplePluginProtocolInfo), /* struct_size */
	NULL/*mt_account_text*/,     /* get_account_text_table */
	NULL,                /* initiate_media */
	NULL,                /* can_do_media */
	NULL,                /* get_moods */
	NULL,                /* set_public_alias */
	NULL                 /* get_public_alias */
#if PURPLE_MAJOR_VERSION == 2 && PURPLE_MINOR_VERSION >= 8
,	NULL,                /* add_buddy_with_invite */
	NULL                 /* add_buddies_with_invite */
#endif
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
/*	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL, /* type */
	NULL, /* ui_requirement */
	0, /* flags */
	NULL, /* dependencies */
	PURPLE_PRIORITY_DEFAULT, /* priority */
	"prpl-eionrobb-pushbullet", /* id */
	"PushBullet", /* name */
	"1.0", /* version */
	"Send SMS through your Android mobile via the PushBullet service", /* summary */
	"", /* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	"", /* homepage */
	plugin_load, /* load */
	plugin_unload, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	&prpl_info, /* extra_info */
	NULL, /* prefs_info */
	NULL/*plugin_actions*/, /* actions */
	NULL, /* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(pushbullet, plugin_init, info);
