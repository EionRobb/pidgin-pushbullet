#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

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
#include <core.h>
#include <debug.h>
#include <prpl.h>
#include <request.h>
#include <version.h>

#ifndef _
#	define _(a) (a)
#endif

#define PB_IS_SMS(a) (((a[0] == '+' || a[0] == '(') && g_ascii_isdigit(a[1])) || g_ascii_isdigit(a[0]))

typedef struct {
	gchar *access_token;
	PurpleSslConnection *websocket;
	gboolean websocket_header_received;
	
	PurpleAccount *account;
	PurpleConnection *pc;
	
	GHashTable *sent_messages_hash;
	guint next_message_id;
	
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

static gchar *
pb_get_next_id(PushBulletAccount *pba)
{
	return g_strdup_printf("purple%x", g_random_int());
}

static void
pb_set_base64_icon_for_buddy(const gchar *base64_icon, PurpleBuddy *buddy)
{
	PurpleBuddyIcon *icon;
	guchar *icon_data;
	gsize icon_len;
	gchar *checksum;
	const gchar *old_checksum;
	
	checksum = g_strdup_printf("%ud", g_str_hash(base64_icon));
	old_checksum = purple_buddy_icons_get_checksum_for_user(buddy);
	if (old_checksum && purple_strequal(old_checksum, checksum)) {
		g_free(checksum);
		return;
	}
	
	icon_data = purple_base64_decode(base64_icon, &icon_len);
	
	icon = purple_buddy_icon_new(purple_buddy_get_account(buddy), purple_buddy_get_name(buddy), icon_data, icon_len, checksum);
	
	g_free(icon_data);
	g_free(checksum);
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
		
		purple_debug_misc("pushbullet", "Got response: %s\n", url_text);
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
	
	//Use the full 'url' until libpurple can handle path's longer than 256 chars
	g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), path);
	//g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), url);
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
    
    g_free(host);
    g_free(path);
    g_free(user);
    g_free(password);
    
    purple_util_fetch_url_request_len_with_account(pba->account, url, FALSE, "Pidgin", TRUE, headers->str, FALSE, 6553500, pb_response_callback, conn);
	
	g_string_free(headers, TRUE);
}

static void pb_start_polling(PushBulletAccount *pba);
static void pb_get_everything_since(PushBulletAccount *pba, gint timestamp);
static void pb_get_phone_threads(PushBulletAccount *pba, const gchar *device);

static void
pb_process_frame(PushBulletAccount *pba, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	
	purple_debug_info("pushbullet", "got frame data: %s\n", frame);
	
	if (!json_parser_load_from_data(parser, frame, -1, NULL))
	{
		purple_debug_error("pushbullet", "Error parsing response: %s\n", frame);
		return;
	}
	
	root = json_parser_get_root(parser);
	
	if (root != NULL) {
		JsonObject *message = json_node_get_object(root);
		const gchar *type = json_object_get_string_member(message, "type");
		if (purple_strequal(type, "tickle")) {
			pb_get_everything_since(pba, purple_account_get_int(pba->account, "last_message_timestamp", 0));
		} else if (purple_strequal(type, "push")) {
			JsonObject *push = json_object_get_object_member(message, "push");
			//{"type":"push","targets":["stream","android","ios"],"push":{"guid":"purple6e94d282","type":"messaging_extension_reply","package_name":"com.pushbullet.android","target_device_iden":"uffvytgsjAoIRwhIL6","conversation_iden":"+6421478252","message":"test2"}}
			//{"type":"push","targets":["stream"],"push":{"type":"sms_changed"}}
			type = json_object_get_string_member(push, "type");
			if (purple_strequal(type, "sms_changed")) {
				pb_get_phone_threads(pba, NULL);
			}
		}
	}
	
	g_object_unref(parser);
}

static void
pb_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	PushBulletAccount *pba = userdata;
	gchar *frame;
	guchar packet_code, length_code;
	guint64 frame_len;
	int read_len = 0;
	gboolean done_some_reads = FALSE;
	
	
	if (G_UNLIKELY(!pba->websocket_header_received)) {
		// HTTP/1.1 101 Switching Protocols
		// Server: nginx
		// Date: Sun, 19 Jul 2015 23:44:27 GMT
		// Connection: upgrade
		// Upgrade: websocket
		// Sec-WebSocket-Accept: pUDN5Js0uDN5KhEWoPJGLyTqwME=
		// Expires: 0
		// Cache-Control: no-cache
		gint nlbr_count = 0;
		gchar nextchar;
		
		while(nlbr_count < 4 && purple_ssl_read(conn, &nextchar, 1)) {
			if (nextchar == '\r' || nextchar == '\n') {
				nlbr_count++;
			} else {
				nlbr_count = 0;
			}
		}
		
		pba->websocket_header_received = TRUE;
		done_some_reads = TRUE;
	}
	
	packet_code = 0;
	while((read_len = purple_ssl_read(conn, &packet_code, 1)) == 1) {
		done_some_reads = TRUE;
		if (packet_code != 129) {
			if (packet_code == 136) {
				purple_debug_error("pushbullet", "websocket closed\n");
				
				purple_ssl_close(conn);
				pba->websocket = NULL;
				pba->websocket_header_received = FALSE;
				
				// revert to polling
				pb_start_polling(pba);
				
				return;
			}
			purple_debug_error("pushbullet", "unknown websocket error %d\n", packet_code);
			return;
		}
		
		length_code = 0;
		purple_ssl_read(conn, &length_code, 1);
		if (length_code <= 125) {
			frame_len = length_code;
		} else if (length_code == 126) {
			guchar len_buf[2];
			purple_ssl_read(conn, len_buf, 2);
			frame_len = (len_buf[1] << 8) + len_buf[0];
		} else if (length_code == 127) {
			purple_ssl_read(conn, &frame_len, 8);
			frame_len = GUINT64_FROM_BE(frame_len);
		}
		purple_debug_info("pushbullet", "frame_len: %d\n", frame_len);
		
		frame = g_new0(gchar, frame_len + 1);
		purple_ssl_read(conn, frame, frame_len);
		
		pb_process_frame(pba, frame);
		
		g_free(frame);
		packet_code = 0;
	}
	
	if (done_some_reads == FALSE && read_len == 0) {
		purple_connection_error_reason(pba->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
	}
}

static void
pb_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	PushBulletAccount *pba = userdata;
	gchar *websocket_header;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy
	
	purple_ssl_input_add(pba->websocket, pb_socket_got_data, pba);
	
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
	
	pba->websocket = NULL;
	pba->websocket_header_received = FALSE;
	
	// revert to polling
	pb_start_polling(pba);
}

static void
pb_start_socket(PushBulletAccount *pba)
{
	pba->websocket = purple_ssl_connect(pba->account, "stream.pushbullet.com", 443, pb_socket_connected, pb_socket_failed, pba);
}


static int 
pb_send_im(PurpleConnection *pc, const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
	PushBulletAccount *pba = pc->proto_data;
	gchar *stripped, *postdata;
	gchar *guid;
	
	if (g_str_has_prefix(message, "?OTR"))
		return 0;
	
	if (PB_IS_SMS(who))
	{
		JsonObject *root = json_object_new();
		JsonObject *data = json_object_new();
		JsonArray *addresses = json_array_new();
		
		json_array_add_string_element(addresses, who);
		json_object_set_array_member(data, "addresses", addresses);
		
		guid = pb_get_next_id(pba);
		json_object_set_string_member(data, "guid", guid);
		json_object_set_string_member(data, "target_device_iden", pba->main_sms_device);
		json_object_set_boolean_member(data, "encrypted", FALSE);
		
		stripped = g_strstrip(purple_markup_strip_html(message));
		json_object_set_string_member(data, "message", stripped);
		g_free(stripped);
		
		json_object_set_object_member(root, "data", data);
		
		postdata = pb_jsonobj_to_string(root);
		pb_fetch_url(pba, "https://api.pushbullet.com/v3/create-text", postdata, NULL, NULL);
		g_free(postdata);
		
		json_object_unref(root);
		
		g_hash_table_insert(pba->sent_messages_hash, guid, guid);
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
		
		guid = pb_get_next_id(pba);
		json_object_set_string_member(root, "guid", guid);
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
		
		g_hash_table_insert(pba->sent_messages_hash, guid, guid);
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
pb_got_conv_image(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	PurpleConversation *conv = user_data;
	gint icon_id;
	gchar *msg_tmp;
	
	if (!url_text || !url_text[0] || url_text[0] == '{')
		return;
	
	icon_id = purple_imgstore_add_with_id((gpointer)url_text, len, NULL);
	
	msg_tmp = g_strdup_printf("<img id='%d'>", icon_id);
	purple_conversation_write(conv, conv->name, msg_tmp, PURPLE_MESSAGE_SYSTEM, time(NULL));
	g_free(msg_tmp);
	
	purple_imgstore_unref_by_id(icon_id);
}

static void
pb_download_image_to_conv(const gchar *url, PurpleConversation *conv)
{
	purple_util_fetch_url_request_len_with_account(purple_conversation_get_account(conv), url, TRUE, "Pidgin", TRUE, NULL, FALSE, 6553500, pb_got_conv_image, conv);
}

static void
pb_got_phone_thread(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	PurpleAccount *account = pba->account;
	PurpleConnection *pc = pba->pc;
	JsonObject *rootobj = json_node_get_object(node);
	JsonObject *data = json_object_get_object_member(rootobj, "data");
	JsonArray *thread = json_object_get_array_member(data, "thread");
	gint i;
	guint len;
	gchar *from = user_data;
	PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, account);
	gint purple_last_message_timestamp = purple_account_get_int(account, "last_message_timestamp", 0);
	gint newest_phone_message_id = purple_account_get_int(account, "newest_phone_message_id", 0);
	
	/*
	{"id":"652","type":"sms","timestamp":1440484608,"direction":"outgoing","body":"message","status":"sent"},
	{"id":"5","type":"mms","timestamp":1440484096,"direction":"incoming","recipient_index":0,"body":"","image_urls":["url1234"]}
	*/
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
				const gchar *guid = json_object_get_string_member(message, "guid");
				if (!guid || !g_hash_table_remove(pba->sent_messages_hash, guid)) {
					if (conv == NULL)
					{
						conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from);
					}
					purple_conversation_write(conv, from, body_html, PURPLE_MESSAGE_SEND, timestamp);
				}
			}
			g_free(body_html);
			
			if (json_object_has_member(message, "image_urls")) {
				JsonArray *image_urls = json_object_get_array_member(message, "image_urls");
				guint j, image_urls_len;
				
				if (conv == NULL)
				{
					conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from);
				}
				
				for(j = 0, image_urls_len = json_array_get_length(image_urls); j < image_urls_len; j++) {
					const gchar *image_url = json_array_get_string_element(thread, j);
					
					pb_download_image_to_conv(image_url, conv);
				}
			}
			
			purple_account_set_int(account, "last_message_timestamp", MAX(purple_account_get_int(account, "last_message_timestamp", 0), timestamp));
			purple_account_set_int(account, "newest_phone_message_id", MAX(purple_account_get_int(account, "newest_phone_message_id", 0), id));
		}
	}
	
	g_free(from);
}

static void
pb_get_phone_thread_by_id(PushBulletAccount *pba, const gchar *device, const gchar *id, const gchar *from)
{
	gchar *postdata;
	gchar *from_copy;
	const gchar *thread_url = "https://api.pushbullet.com/v3/get-permanent";
	
	if (id == NULL || id[0] == '\0')
		return;
	
	if (device == NULL) {
		device = pba->main_sms_device;
	}
	if (device == NULL) {
		purple_debug_error("pushbullet", "No SMS device to download threads from\n");
		return;
	}
	from_copy = g_strdup(from);

	postdata = g_strdup_printf("{\"key\":\"%s_thread_%s\"}", device, id);
	
	pb_fetch_url(pba, thread_url, postdata, pb_got_phone_thread, from_copy);
	
	g_free(postdata);
}

static void
pb_got_phone_threads(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	PurpleAccount *account = pba->account;
	JsonObject *rootobj = json_node_get_object(node);
	JsonObject *data = json_object_get_object_member(rootobj, "data");
	JsonArray *threads = json_object_get_array_member(data, "threads");
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
			
			if (json_object_has_member(first_recipient, "thumbnail")) {
				pb_set_base64_icon_for_buddy(json_object_get_string_member(first_recipient, "thumbnail"), purple_find_buddy(account, from));
			}
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
	const gchar *phonebook_url = "https://api.pushbullet.com/v3/get-permanent";
	gchar *device_copy;
	gchar *postdata;
	
	if (device == NULL) {
		device = pba->main_sms_device;
	}
	if (device == NULL) {
		purple_debug_error("pushbullet", "No SMS device to download threads from\n");
		return;
	}
	device_copy = g_strdup(device);

	postdata = g_strdup_printf("{\"key\":\"%s_threads\"}", device_copy);
	
	pb_fetch_url(pba, phonebook_url, postdata, pb_got_phone_threads, device_copy);
	
	g_free(postdata);
}

static gboolean
pb_poll_phone_threads(PushBulletAccount *pba)
{
	if (purple_account_is_connected(pba->account) && pba->main_sms_device) {
		pb_get_phone_threads(pba, NULL);
		return TRUE;
	}
	
	pba->phone_threads_poll = 0;
	
	return FALSE;
}

static gboolean
pb_poll_everything(PushBulletAccount *pba)
{
	if (purple_account_is_connected(pba->account)) {
		pb_get_everything_since(pba, purple_account_get_int(pba->account, "last_message_timestamp", 0));
		return TRUE;
	}
	
	pba->everything_poll = 0;
	
	return FALSE;
}

static void
pb_start_polling(PushBulletAccount *pba)
{
	if (!purple_account_is_connected(pba->account))
		return;
	
	if (!pba->phone_threads_poll && pba->main_sms_device) {
		pb_get_phone_threads(pba, NULL);
		pba->phone_threads_poll = purple_timeout_add_seconds(10, (GSourceFunc) pb_poll_phone_threads, pba);
	}
	
	if (!pba->everything_poll) {
		pb_get_everything_since(pba, purple_account_get_int(pba->account, "last_message_timestamp", 0));
		pba->everything_poll = purple_timeout_add_seconds(10, (GSourceFunc) pb_poll_everything, pba);
	}
}

static void
pb_got_phonebook(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	PurpleAccount *account = pba->account;
	JsonObject *rootobj = json_node_get_object(node);
	JsonObject *data = json_object_get_object_member(rootobj, "data");
	JsonArray *phonebook = json_object_get_array_member(data, "phonebook");
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
	gchar *postdata;
	gchar *device_copy;
	
	if (device == NULL) {
		device = pba->main_sms_device;
	}
	device_copy = g_strdup(device);

	postdata = g_strdup_printf("{\"key\":\"phonebook_%s\"}", purple_url_encode(device_copy));
	
	pb_fetch_url(pba, "https://api.pushbullet.com/v3/get-permanent", postdata, pb_got_phonebook, device_copy);
	
	g_free(postdata);
}

static void
pb_got_everything(PushBulletAccount *pba, JsonNode *node, gpointer user_data)
{
	JsonObject *rootobj = json_node_get_object(node);
	JsonArray *devices = json_object_has_member(rootobj, "devices") ? json_object_get_array_member(rootobj, "devices") : NULL;
	JsonArray *pushes = json_object_has_member(rootobj, "pushes") ? json_object_get_array_member(rootobj, "pushes") : NULL;
	JsonArray *contacts = json_object_has_member(rootobj, "contacts") ? json_object_get_array_member(rootobj, "contacts") : NULL;
	JsonArray *chats = json_object_has_member(rootobj, "chats") ? json_object_get_array_member(rootobj, "chats") : NULL;
	gint i;
	guint len;
	PurpleGroup *pbgroup;
	
	pbgroup = purple_find_group("PushBullet");
	if (!pbgroup)
	{
		pbgroup = purple_group_new("PushBullet");
		purple_blist_add_group(pbgroup, NULL);
	}
	
	if (json_object_has_member(rootobj, "error")) {
		JsonObject *error = json_object_get_object_member(rootobj, "error");
		const gchar *type = json_object_get_string_member(error, "type");
		const gchar *message = json_object_get_string_member(error, "message");
		
		//TODO check type
		purple_connection_error_reason(pba->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, message);
		return;
	}
	
	if (devices != NULL) {
		for(i = 0, len = json_array_get_length(devices); i < len; i++) {
			JsonObject *device = json_array_get_object_element(devices, i);
			
			if (pba->main_sms_device == NULL && json_object_get_boolean_member(device, "has_sms")) {
				pba->main_sms_device = g_strdup(json_object_get_string_member(device, "iden"));
				purple_account_set_string(pba->account, "main_sms_device", pba->main_sms_device);
				
				pb_get_phonebook(pba, pba->main_sms_device);
				
				if (!pba->websocket) {
					pb_start_polling(pba);
				}
				
				break; //TODO handle more than one
			}
		}
	}
	
	if (pushes != NULL) {
		gint last_message_timestamp = purple_account_get_int(pba->account, "last_message_timestamp", 0);
		for(i = json_array_get_length(pushes); i > 0; i--) {
			JsonObject *push = json_array_get_object_element(pushes, i - 1);
			const gchar *type = json_object_get_string_member(push, "type");
			gdouble modified;
			time_t timestamp;
			gboolean dismissed;
			
			if (!type)
				continue;
			
			modified = json_object_get_double_member(push, "modified");
			timestamp = (time_t) modified;
			dismissed = json_object_get_boolean_member(push, "dismissed");
			
			if (timestamp <= last_message_timestamp || dismissed) {
				continue;
			}
			
			// {"active":true,"iden":"uffvytgsjApuAUIFRk","created":1.438895081423904e+09,"modified":1.438895081432786e+09,"type":"file","dismissed":false,"guid":"153b70f0-f7a6-4db9-a6f4-28b99fa416f1","direction":"self","sender_iden":"uffvytg","sender_email":"eionrobb@gmail.com","sender_email_normalized":"eionrobb@gmail.com","sender_name":"Eion Robb","receiver_iden":"uffvytg","receiver_email":"eionrobb@gmail.com","receiver_email_normalized":"eionrobb@gmail.com","target_device_iden":"uffvytgsjz7O3P0Jl6","source_device_iden":"uffvytgsjAoIRwhIL6","file_name":"IMG_20150807_084618.jpg","file_type":"image/jpeg","file_url":"https://dl.pushbulletusercontent.com/FHOZdyzfvnoYZY0DP6oK1rGKiJpWCPc0/IMG_20150807_084618.jpg","image_width":4128,"image_height":2322,"image_url":"https://lh3.googleusercontent.com/WY5TK7h3mzD32qMcnxtqt-4PrYcWW1uWDHnRW2x1oJK8mnYk2v4HbZrRjIQkiYdxMKQSdNI8GGPqfO6s6tEyuRVLzeA"}
			
			if (purple_strequal(type, "note") || purple_strequal(type, "link") || purple_strequal(type, "file")) {
				const gchar *from = json_object_get_string_member(push, "sender_email_normalized");
				const gchar *body = json_object_get_string_member(push, "body");
				const gchar *direction = json_object_get_string_member(push, "direction");
				gchar *body_html;
				
				if (from == NULL) {
					if (!json_object_has_member(push, "sender_name")) {
						purple_debug_error("pushbullet", "no sender name/email\n");
						continue;
					}
					from = json_object_get_string_member(push, "sender_name");
				}
				
				if (body && *body) {
					body_html = purple_strdup_withhtml(body);
				} else {
					const gchar *title = json_object_get_string_member(push, "title");
					if (title && *title) {
						body_html = purple_strdup_withhtml(title);
					} else {
						body_html = "Message";
					}
				}
				
				if (json_object_has_member(push, "url")) {
					gchar *body_with_link = g_strconcat("<a href=\"", json_object_get_string_member(push, "url"), "\">", body_html, "</a>", NULL);
					g_free(body_html);
					body_html = body_with_link;
					
				} else if (json_object_has_member(push, "image_url")) {
					const gchar *image_url = json_object_get_string_member(push, "image_url");
					PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, pba->account);
					
					if (conv == NULL)
					{
						conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, pba->account, from);
					}
					pb_download_image_to_conv(image_url, conv);
					
				} else if (json_object_has_member(push, "file_url")) {
					gchar *body_with_link;
					const gchar *file_name = json_object_get_string_member(push, "file_name");
					
					if (file_name && *file_name) {
						g_free(body_html);
						body_html = purple_strdup_withhtml(file_name);
					}
					
					body_with_link= g_strconcat("<a href=\"", json_object_get_string_member(push, "file_url"), "\">", json_object_get_string_member(push, "file_name"), "</a>", NULL);
					g_free(body_html);
					body_html = body_with_link;
				}
				
				if (direction[0] != 'o') {
					serv_got_im(pba->pc, from, body_html, PURPLE_MESSAGE_RECV, timestamp);
				} else {
					const gchar *guid = json_object_get_string_member(push, "guid");
					from = json_object_get_string_member(push, "receiver_email_normalized");
					
					if (!guid || !g_hash_table_remove(pba->sent_messages_hash, guid)) {
						PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, pba->account);
						if (conv == NULL)
						{
							conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, pba->account, from);
						}
						purple_conversation_write(conv, from, body_html, PURPLE_MESSAGE_SEND, timestamp);
					}
				}
				
				g_free(body_html);
			}
				
			purple_account_set_int(pba->account, "last_message_timestamp", MAX(purple_account_get_int(pba->account, "last_message_timestamp", 0), timestamp));
		}
	}
	
	if (contacts != NULL) {
		for(i = 0, len = json_array_get_length(contacts); i < len; i++) {
			JsonObject *contact = json_array_get_object_element(contacts, i);
			const gchar *email = json_object_get_string_member(contact, "email_normalized");
			const gchar *name = json_object_get_string_member(contact, "name");
			const gchar *image_url = json_object_get_string_member(contact, "image_url");
			
			PurpleBuddy *buddy = purple_find_buddy(pba->account, email);
			if (buddy == NULL)
			{
				buddy = purple_buddy_new(pba->account, email, name);
				purple_blist_add_buddy(buddy, NULL, pbgroup, NULL);
			}
			purple_prpl_got_user_status(pba->account, email, purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE), NULL);
		}
	}
	
	if (chats != NULL) {
		for(i = 0, len = json_array_get_length(chats); i < len; i++) {
			JsonObject *chat = json_array_get_object_element(chats, i);
			JsonObject *contact = json_object_get_object_member(chat, "with");
			const gchar *email = json_object_get_string_member(contact, "email_normalized");
			const gchar *name = json_object_get_string_member(contact, "name");
			const gchar *image_url = json_object_get_string_member(contact, "image_url");
			
			PurpleBuddy *buddy = purple_find_buddy(pba->account, email);
			if (buddy == NULL)
			{
				buddy = purple_buddy_new(pba->account, email, name);
				purple_blist_add_buddy(buddy, NULL, pbgroup, NULL);
			}
			purple_prpl_got_user_status(pba->account, email, purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE), NULL);
		}
	}
}

static void
pb_get_everything(PushBulletAccount *pba)
{
	pb_fetch_url(pba, "https://api.pushbullet.com/v2/pushes", NULL, pb_got_everything, NULL);
	pb_fetch_url(pba, "https://api.pushbullet.com/v2/devices", NULL, pb_got_everything, NULL);
	pb_fetch_url(pba, "https://api.pushbullet.com/v2/contacts", NULL, pb_got_everything, NULL);
	pb_fetch_url(pba, "https://api.pushbullet.com/v2/chats", NULL, pb_got_everything, NULL);
}

static void
pb_get_everything_since(PushBulletAccount *pba, gint timestamp)
{
	gchar *url;
	
	url = g_strdup_printf("https://api.pushbullet.com/v2/pushes?modified_after=%d", timestamp);
	pb_fetch_url(pba, url, NULL, pb_got_everything, NULL);
	g_free(url);
	
	url = g_strdup_printf("https://api.pushbullet.com/v2/devices?modified_after=%d", timestamp);
	pb_fetch_url(pba, url, NULL, pb_got_everything, NULL);
	g_free(url);
	
	url = g_strdup_printf("https://api.pushbullet.com/v2/contacts?modified_after=%d", timestamp);
	pb_fetch_url(pba, url, NULL, pb_got_everything, NULL);
	g_free(url);
	
	url = g_strdup_printf("https://api.pushbullet.com/v2/chats?modified_after=%d", timestamp);
	pb_fetch_url(pba, url, NULL, pb_got_everything, NULL);
	g_free(url);
}



void
pb_add_buddy_with_invite(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group, const char* message)
{
	PushBulletAccount *pba = pc->proto_data;
	const gchar *contacts_url = "https://api.pushbullet.com/v2/contacts";
	GString *postdata;
	const gchar *buddy_name;
	
	buddy_name = purple_buddy_get_name(buddy);
	if (!PB_IS_SMS(buddy_name)) {
		postdata = g_string_new(NULL);
		g_string_append_printf(postdata, "name=%s", purple_url_encode(purple_buddy_get_alias(buddy)));
		g_string_append_printf(postdata, "email=%s", purple_url_encode(buddy_name));
		
		pb_fetch_url(pba, contacts_url, postdata->str, NULL, NULL);
		
		g_string_free(postdata, TRUE);
		purple_prpl_got_user_status(pba->account, buddy_name, purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE), NULL);
	} else {
		
		purple_prpl_got_user_status(pba->account, buddy_name, "mobile", NULL);
		purple_prpl_got_user_status(pba->account, buddy_name, purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE), NULL);
	}
}

void 
pb_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	pb_add_buddy_with_invite(gc, buddy, group, _("Please authorize me so I can add you to my buddy list."));
}


static void
pb_oauth_set_access_token_cb(gpointer data, const gchar *access_token)
{
	PurpleAccount *account = data;
	gchar *real_access_token;
	const gchar *access_token_start;
	const gchar *access_token_end;
	gchar *strtmp;
	
	if (!access_token || !(*access_token)) {
		return;
	}
	
	if((access_token_start = strstr(access_token, "access_token=")))
	{
		access_token_start += 13;
		access_token_end = strchr(access_token_start, '&');
		if (access_token_end)
			real_access_token = g_strndup(access_token_start, access_token_end - access_token_start);
		else
			real_access_token = g_strdup(access_token_start);
		
		strtmp = g_strdup(purple_url_decode(real_access_token));
		g_free(real_access_token);
		real_access_token = strtmp;
	} else {
		real_access_token = g_strdup(access_token);
	}
	
	if (real_access_token && *real_access_token) {
		purple_account_set_remember_password(account, TRUE);
		purple_account_set_password(account, real_access_token);
		
		purple_account_set_enabled(account, purple_core_get_ui(), TRUE);
		purple_account_connect(account);
	}
	
	g_free(real_access_token);
}


static void
pb_oauth_request_access_token(PurpleAccount *account)
{
	purple_notify_uri(account, "https://www.pushbullet.com/authorize?client_id=0m8Tcu8rNSBxeWL65e6nTKmqXqZSIKEe&redirect_uri=https%3A%2F%2Fwww.pushbullet.com%2Flogin-success&response_type=token&scope=everything");
	
	purple_request_input(NULL, NULL, _("Set your Access Token"),
					_("Copy the Success URL you are sent to after you accept"), NULL,
					FALSE, FALSE, "https://www.pushbullet.com/login-success#access_token=...", 
					_("OK"), G_CALLBACK(pb_oauth_set_access_token_cb), 
					_("Cancel"), NULL, account, NULL, NULL, account);
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
	
	pba->sent_messages_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	
	pc->proto_data = pba;
	
	password = purple_account_get_password(account);
	if (password && *password) {
		pba->access_token = g_strdup(password);
	} else {
		pb_oauth_request_access_token(account);
		purple_connection_error_reason(pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, _("Access Token required"));
		
		return;
	}
	
	if(pba->access_token)
	{
		purple_connection_set_state(pc, PURPLE_CONNECTED);
		
		pb_start_socket(pba);
		
		if (purple_account_get_string(account, "main_sms_device", NULL) != NULL) {
			pba->main_sms_device = g_strdup(purple_account_get_string(account, "main_sms_device", NULL));
			pb_get_phonebook(pba, pba->main_sms_device);
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
	purple_timeout_remove(pba->everything_poll);
	purple_ssl_close(pba->websocket);
	
	g_hash_table_destroy(pba->sent_messages_hash); pba->sent_messages_hash = NULL;
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
	OPT_PROTO_SLASH_COMMANDS_NATIVE | OPT_PROTO_PASSWORD_OPTIONAL/*|OPT_PROTO_IM_IMAGE*/,

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
	pb_add_buddy,        /* add_buddy */
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
,	pb_add_buddy_with_invite, /* add_buddy_with_invite */
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
